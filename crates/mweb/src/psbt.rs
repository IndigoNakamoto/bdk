//! ltcsuite-compatible PSBTv2 MWEB key types and maps.
//!
//! Key codes match [`ltcsuite/ltcd` `ltcutil/psbt/types.go`](https://github.com/ltcsuite/ltcd/blob/master/ltcutil/psbt/types.go)
//! (first-class `0x90+` types — not BIP174 `0xFC` proprietary blobs).
//!
//! Lives in `bdk_mweb` until the published `litecoin` crate grows native PSBTv2 + MWEB maps.
//! Values serialize into [`bitcoin::psbt::Psbt`] `unknown` maps plus a parallel kernel list.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::blockdata::mimblewimble::{Kernel, Output, Transaction as MwebTransaction};
use bitcoin::consensus::serialize;
use bitcoin::psbt::{raw, Psbt};
use bitcoin::Transaction;

use crate::error::Error;
use crate::tx_builder::{FinishedMwebPegin, FinishedMwebTx};

// --- Global ---

/// `MwebTxOffsetType`
pub const MWEB_TX_OFFSET_TYPE: u8 = 0x90;
/// `MwebTxStealthOffsetType`
pub const MWEB_TX_STEALTH_OFFSET_TYPE: u8 = 0x91;
/// `MwebKernelCountType`
pub const MWEB_KERNEL_COUNT_TYPE: u8 = 0x92;

// --- Input ---

/// `MwebSpentOutputIdType`
pub const MWEB_SPENT_OUTPUT_ID_TYPE: u8 = 0x90;
/// `MwebSpentOutputCommitType`
pub const MWEB_SPENT_OUTPUT_COMMIT_TYPE: u8 = 0x91;
/// `MwebSpentOutputPubKeyType`
pub const MWEB_SPENT_OUTPUT_PUBKEY_TYPE: u8 = 0x92;
/// `MwebInputPubKeyType`
pub const MWEB_INPUT_PUBKEY_TYPE: u8 = 0x93;
/// `MwebInputFeaturesType`
pub const MWEB_INPUT_FEATURES_TYPE: u8 = 0x94;
/// `MwebInputSignatureType`
pub const MWEB_INPUT_SIGNATURE_TYPE: u8 = 0x95;
/// `MwebAddressIndexType`
pub const MWEB_ADDRESS_INDEX_TYPE: u8 = 0x96;
/// `MwebInputAmountType`
pub const MWEB_INPUT_AMOUNT_TYPE: u8 = 0x97;
/// `MwebSharedSecretType`
pub const MWEB_SHARED_SECRET_TYPE: u8 = 0x98;
/// `MwebKeyExchangePubKeyType`
pub const MWEB_KEY_EXCHANGE_PUBKEY_TYPE: u8 = 0x99;
/// `MwebMasterScanKeyOriginType`
pub const MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE: u8 = 0x9A;
/// `MwebMasterSpendKeyOriginType`
pub const MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE: u8 = 0x9B;
/// `MwebInputExtraDataType`
pub const MWEB_INPUT_EXTRA_DATA_TYPE: u8 = 0x9C;

// --- Output ---

/// `MwebStealthAddressOutputType`
pub const MWEB_STEALTH_ADDRESS_OUTPUT_TYPE: u8 = 0x90;
/// `MwebCommitOutputType`
pub const MWEB_COMMIT_OUTPUT_TYPE: u8 = 0x91;
/// `MwebFeaturesOutputType`
pub const MWEB_FEATURES_OUTPUT_TYPE: u8 = 0x92;
/// `MwebSenderPubKeyOutputType`
pub const MWEB_SENDER_PUBKEY_OUTPUT_TYPE: u8 = 0x93;
/// `MwebOutputPubKeyOutputType`
pub const MWEB_OUTPUT_PUBKEY_OUTPUT_TYPE: u8 = 0x94;
/// `MwebStandardFieldsOutputType`
pub const MWEB_STANDARD_FIELDS_OUTPUT_TYPE: u8 = 0x95;
/// `MwebRangeProofOutputType`
pub const MWEB_RANGE_PROOF_OUTPUT_TYPE: u8 = 0x96;
/// `MwebSignatureOutputType`
pub const MWEB_SIGNATURE_OUTPUT_TYPE: u8 = 0x97;
/// `MwebExtraDataOutputType`
pub const MWEB_EXTRA_DATA_OUTPUT_TYPE: u8 = 0x98;

// --- Kernel ---

/// `MwebKernelExcessCommitType`
pub const MWEB_KERNEL_EXCESS_COMMIT_TYPE: u8 = 0;
/// `MwebKernelStealthCommitType`
pub const MWEB_KERNEL_STEALTH_COMMIT_TYPE: u8 = 1;
/// `MwebKernelFeeType`
pub const MWEB_KERNEL_FEE_TYPE: u8 = 2;
/// `MwebKernelPeginAmountType`
pub const MWEB_KERNEL_PEGIN_AMOUNT_TYPE: u8 = 3;
/// `MwebKernelPegoutType`
pub const MWEB_KERNEL_PEGOUT_TYPE: u8 = 4;
/// `MwebKernelLockHeightType`
pub const MWEB_KERNEL_LOCK_HEIGHT_TYPE: u8 = 5;
/// `MwebKernelFeaturesType`
pub const MWEB_KERNEL_FEATURES_TYPE: u8 = 6;
/// `MwebKernelExtraDataType`
pub const MWEB_KERNEL_EXTRA_DATA_TYPE: u8 = 7;
/// `MwebKernelSignatureType`
pub const MWEB_KERNEL_SIGNATURE_TYPE: u8 = 8;

fn kv(type_value: u8, value: Vec<u8>) -> (raw::Key, Vec<u8>) {
    (
        raw::Key {
            type_value,
            key: Vec::new(),
        },
        value,
    )
}

/// MWEB fields for one PSBT input (ltcd `PInput` MWEB subset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MwebPsbtInput {
    /// Spent output id.
    pub output_id: Option<[u8; 32]>,
    /// Spent commitment (33 bytes).
    pub commit: Option<[u8; 33]>,
    /// Output pubkey.
    pub output_pubkey: Option<Vec<u8>>,
    /// Input pubkey.
    pub input_pubkey: Option<Vec<u8>>,
    /// Feature bits.
    pub features: Option<u8>,
    /// Input signature.
    pub signature: Option<Vec<u8>>,
    /// Address index.
    pub address_index: Option<u32>,
    /// Amount litoshis.
    pub amount: Option<u64>,
    /// Shared secret.
    pub shared_secret: Option<[u8; 32]>,
    /// Key exchange pubkey.
    pub key_exchange_pubkey: Option<Vec<u8>>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
}

impl MwebPsbtInput {
    /// Encode as PSBT unknown key-value pairs (`0x90+`).
    pub fn to_unknown_map(&self) -> BTreeMap<raw::Key, Vec<u8>> {
        let mut m = BTreeMap::new();
        if let Some(id) = self.output_id {
            let (k, v) = kv(MWEB_SPENT_OUTPUT_ID_TYPE, id.to_vec());
            m.insert(k, v);
        }
        if let Some(c) = self.commit {
            let (k, v) = kv(MWEB_SPENT_OUTPUT_COMMIT_TYPE, c.to_vec());
            m.insert(k, v);
        }
        if let Some(ref p) = self.output_pubkey {
            let (k, v) = kv(MWEB_SPENT_OUTPUT_PUBKEY_TYPE, p.clone());
            m.insert(k, v);
        }
        if let Some(ref p) = self.input_pubkey {
            let (k, v) = kv(MWEB_INPUT_PUBKEY_TYPE, p.clone());
            m.insert(k, v);
        }
        if let Some(f) = self.features {
            let (k, v) = kv(MWEB_INPUT_FEATURES_TYPE, vec![f]);
            m.insert(k, v);
        }
        if let Some(ref s) = self.signature {
            let (k, v) = kv(MWEB_INPUT_SIGNATURE_TYPE, s.clone());
            m.insert(k, v);
        }
        if let Some(i) = self.address_index {
            let (k, v) = kv(MWEB_ADDRESS_INDEX_TYPE, i.to_le_bytes().to_vec());
            m.insert(k, v);
        }
        if let Some(a) = self.amount {
            let (k, v) = kv(MWEB_INPUT_AMOUNT_TYPE, a.to_le_bytes().to_vec());
            m.insert(k, v);
        }
        if let Some(ss) = self.shared_secret {
            let (k, v) = kv(MWEB_SHARED_SECRET_TYPE, ss.to_vec());
            m.insert(k, v);
        }
        if let Some(ref p) = self.key_exchange_pubkey {
            let (k, v) = kv(MWEB_KEY_EXCHANGE_PUBKEY_TYPE, p.clone());
            m.insert(k, v);
        }
        if let Some(ref e) = self.extra_data {
            let (k, v) = kv(MWEB_INPUT_EXTRA_DATA_TYPE, e.clone());
            m.insert(k, v);
        }
        m
    }

    /// Parse from a PSBT input `unknown` map (MWEB `0x90+` keys only).
    pub fn from_unknown_map(unknown: &BTreeMap<raw::Key, Vec<u8>>) -> Self {
        let mut out = Self::default();
        for (k, v) in unknown {
            if !k.key.is_empty() {
                continue;
            }
            match k.type_value {
                MWEB_SPENT_OUTPUT_ID_TYPE if v.len() == 32 => {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(v);
                    out.output_id = Some(id);
                }
                MWEB_SPENT_OUTPUT_COMMIT_TYPE if v.len() == 33 => {
                    let mut c = [0u8; 33];
                    c.copy_from_slice(v);
                    out.commit = Some(c);
                }
                MWEB_SPENT_OUTPUT_PUBKEY_TYPE => out.output_pubkey = Some(v.clone()),
                MWEB_INPUT_PUBKEY_TYPE => out.input_pubkey = Some(v.clone()),
                MWEB_INPUT_FEATURES_TYPE if !v.is_empty() => out.features = Some(v[0]),
                MWEB_INPUT_SIGNATURE_TYPE => out.signature = Some(v.clone()),
                MWEB_ADDRESS_INDEX_TYPE if v.len() == 4 => {
                    out.address_index = Some(u32::from_le_bytes(v[..4].try_into().unwrap()));
                }
                MWEB_INPUT_AMOUNT_TYPE if v.len() == 8 => {
                    out.amount = Some(u64::from_le_bytes(v[..8].try_into().unwrap()));
                }
                MWEB_SHARED_SECRET_TYPE if v.len() == 32 => {
                    let mut ss = [0u8; 32];
                    ss.copy_from_slice(v);
                    out.shared_secret = Some(ss);
                }
                MWEB_KEY_EXCHANGE_PUBKEY_TYPE => out.key_exchange_pubkey = Some(v.clone()),
                MWEB_INPUT_EXTRA_DATA_TYPE => out.extra_data = Some(v.clone()),
                _ => {}
            }
        }
        out
    }
}

/// MWEB fields for one PSBT output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MwebPsbtOutput {
    /// Stealth address bytes.
    pub stealth_address: Option<Vec<u8>>,
    /// Commitment.
    pub commit: Option<[u8; 33]>,
    /// Features.
    pub features: Option<u8>,
    /// Sender pubkey.
    pub sender_pubkey: Option<Vec<u8>>,
    /// Output pubkey.
    pub output_pubkey: Option<Vec<u8>>,
    /// Standard fields blob.
    pub standard_fields: Option<Vec<u8>>,
    /// Range proof.
    pub range_proof: Option<Vec<u8>>,
    /// Signature.
    pub signature: Option<Vec<u8>>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
}

impl MwebPsbtOutput {
    /// Encode as PSBT unknown key-value pairs.
    pub fn to_unknown_map(&self) -> BTreeMap<raw::Key, Vec<u8>> {
        let mut m = BTreeMap::new();
        if let Some(ref a) = self.stealth_address {
            let (k, v) = kv(MWEB_STEALTH_ADDRESS_OUTPUT_TYPE, a.clone());
            m.insert(k, v);
        }
        if let Some(c) = self.commit {
            let (k, v) = kv(MWEB_COMMIT_OUTPUT_TYPE, c.to_vec());
            m.insert(k, v);
        }
        if let Some(f) = self.features {
            let (k, v) = kv(MWEB_FEATURES_OUTPUT_TYPE, vec![f]);
            m.insert(k, v);
        }
        if let Some(ref p) = self.sender_pubkey {
            let (k, v) = kv(MWEB_SENDER_PUBKEY_OUTPUT_TYPE, p.clone());
            m.insert(k, v);
        }
        if let Some(ref p) = self.output_pubkey {
            let (k, v) = kv(MWEB_OUTPUT_PUBKEY_OUTPUT_TYPE, p.clone());
            m.insert(k, v);
        }
        if let Some(ref s) = self.standard_fields {
            let (k, v) = kv(MWEB_STANDARD_FIELDS_OUTPUT_TYPE, s.clone());
            m.insert(k, v);
        }
        if let Some(ref r) = self.range_proof {
            let (k, v) = kv(MWEB_RANGE_PROOF_OUTPUT_TYPE, r.clone());
            m.insert(k, v);
        }
        if let Some(ref s) = self.signature {
            let (k, v) = kv(MWEB_SIGNATURE_OUTPUT_TYPE, s.clone());
            m.insert(k, v);
        }
        if let Some(ref e) = self.extra_data {
            let (k, v) = kv(MWEB_EXTRA_DATA_OUTPUT_TYPE, e.clone());
            m.insert(k, v);
        }
        m
    }

    /// Build typed fields from a wire [`Output`].
    pub fn from_mweb_output(output: &Output) -> Self {
        Self {
            commit: Some(output.commitment),
            output_pubkey: Some(output.receiver_public_key.serialize().to_vec()),
            sender_pubkey: Some(output.sender_public_key.serialize().to_vec()),
            features: Some(output.message.features),
            // Standard fields are nested; stash Ke when present (full blob needs OutputMessage encode).
            standard_fields: output.message.standard_fields.as_ref().map(|sf| {
                let mut v = sf.key_exchange_pubkey.serialize().to_vec();
                v.push(sf.view_tag);
                v.extend_from_slice(&sf.masked_value.to_le_bytes());
                v.extend_from_slice(&sf.masked_nonce);
                v
            }),
            range_proof: Some(output.range_proof.to_vec()),
            signature: Some(output.signature.to_vec()),
            stealth_address: None,
            extra_data: if output.message.extra_data.is_empty() {
                None
            } else {
                Some(output.message.extra_data.clone())
            },
        }
    }
}

/// One MWEB kernel PSBT map (ltcd `PKernel`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MwebPsbtKernel {
    /// Excess commitment.
    pub excess_commit: Option<[u8; 33]>,
    /// Stealth excess (33-byte compressed pubkey).
    pub stealth_commit: Option<Vec<u8>>,
    /// Fee (litoshis).
    pub fee: Option<u64>,
    /// Peg-in amount.
    pub pegin_amount: Option<u64>,
    /// Peg-out serialization.
    pub pegout: Option<Vec<u8>>,
    /// Lock height.
    pub lock_height: Option<u32>,
    /// Features.
    pub features: Option<u8>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
    /// Signature (64 bytes).
    pub signature: Option<[u8; 64]>,
}

impl MwebPsbtKernel {
    /// Encode kernel map as typed pairs.
    pub fn to_pairs(&self) -> Vec<(u8, Vec<u8>)> {
        let mut pairs = Vec::new();
        if let Some(c) = self.excess_commit {
            pairs.push((MWEB_KERNEL_EXCESS_COMMIT_TYPE, c.to_vec()));
        }
        if let Some(ref c) = self.stealth_commit {
            pairs.push((MWEB_KERNEL_STEALTH_COMMIT_TYPE, c.clone()));
        }
        if let Some(f) = self.fee {
            pairs.push((MWEB_KERNEL_FEE_TYPE, f.to_le_bytes().to_vec()));
        }
        if let Some(a) = self.pegin_amount {
            pairs.push((MWEB_KERNEL_PEGIN_AMOUNT_TYPE, a.to_le_bytes().to_vec()));
        }
        if let Some(ref p) = self.pegout {
            pairs.push((MWEB_KERNEL_PEGOUT_TYPE, p.clone()));
        }
        if let Some(h) = self.lock_height {
            pairs.push((MWEB_KERNEL_LOCK_HEIGHT_TYPE, h.to_le_bytes().to_vec()));
        }
        if let Some(f) = self.features {
            pairs.push((MWEB_KERNEL_FEATURES_TYPE, vec![f]));
        }
        if let Some(ref e) = self.extra_data {
            pairs.push((MWEB_KERNEL_EXTRA_DATA_TYPE, e.clone()));
        }
        if let Some(s) = self.signature {
            pairs.push((MWEB_KERNEL_SIGNATURE_TYPE, s.to_vec()));
        }
        pairs
    }

    /// Build from a wire [`Kernel`].
    pub fn from_kernel(k: &Kernel) -> Self {
        Self {
            excess_commit: Some(k.excess),
            stealth_commit: k.stealth_excess.map(|pk| pk.serialize().to_vec()),
            fee: k.fee.map(|f| f as u64),
            pegin_amount: k.pegin.map(|a| a as u64),
            pegout: if k.pegouts.is_empty() {
                None
            } else {
                Some(serialize(&k.pegouts))
            },
            lock_height: k.lock_height,
            features: Some(k.features),
            extra_data: if k.extra_data.is_empty() {
                None
            } else {
                Some(k.extra_data.clone())
            },
            signature: Some(k.signature),
        }
    }
}

/// Transparent [`Psbt`] plus MWEB global offsets and kernel maps (ltcd-shaped).
#[derive(Debug, Clone)]
pub struct MwebPsbt {
    /// Underlying BIP174 PSBT (MWEB input/output fields live in `unknown` maps).
    pub psbt: Psbt,
    /// Kernel offset (global `0x90`).
    pub tx_offset: Option<[u8; 32]>,
    /// Stealth offset (global `0x91`).
    pub stealth_offset: Option<[u8; 32]>,
    /// Kernel maps (global kernel count = `kernels.len()`).
    pub kernels: Vec<MwebPsbtKernel>,
    /// Fully assembled MWEB body when known (authoring / extract source).
    pub mw_tx: Option<MwebTransaction>,
}

impl MwebPsbt {
    /// Wrap a transparent PSBT with empty MWEB extension.
    pub fn from_psbt(psbt: Psbt) -> Self {
        Self {
            psbt,
            tx_offset: None,
            stealth_offset: None,
            kernels: Vec::new(),
            mw_tx: None,
        }
    }

    /// Inject MWEB globals into `psbt.unknown`.
    pub fn apply_unknown_maps(&mut self) {
        if let Some(off) = self.tx_offset {
            let (k, v) = kv(MWEB_TX_OFFSET_TYPE, off.to_vec());
            self.psbt.unknown.insert(k, v);
        }
        if let Some(off) = self.stealth_offset {
            let (k, v) = kv(MWEB_TX_STEALTH_OFFSET_TYPE, off.to_vec());
            self.psbt.unknown.insert(k, v);
        }
        let count = self.kernels.len() as u32;
        let (k, v) = kv(MWEB_KERNEL_COUNT_TYPE, count.to_le_bytes().to_vec());
        self.psbt.unknown.insert(k, v);
    }

    fn from_mw_body(mut unsigned: Transaction, mw: MwebTransaction) -> Result<Self, Error> {
        unsigned.mw_tx = None;
        let psbt = Psbt::from_unsigned_tx(unsigned)
            .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;
        let mut m = Self::from_psbt(psbt);
        m.tx_offset = Some(mw.kernel_offset);
        m.stealth_offset = Some(mw.stealth_offset);
        m.kernels = mw.body.kernels.iter().map(MwebPsbtKernel::from_kernel).collect();
        m.mw_tx = Some(mw);
        m.apply_unknown_maps();
        Ok(m)
    }

    /// Populate from a finished MWEB spend / peg-out ([`FinishedMwebTx`]).
    ///
    /// Happy-path extract uses [`Self::extract_tx_with_mweb`] (no separate `attach_mweb_tx`).
    pub fn from_finished_mweb_tx(finished: &FinishedMwebTx) -> Result<Self, Error> {
        let mw = finished
            .tx
            .mw_tx
            .clone()
            .ok_or_else(|| Error::Crypto("FinishedMwebTx missing mw_tx".into()))?;
        let mut m = Self::from_mw_body(finished.tx.clone(), mw)?;
        for (i, coin_id) in finished.spent_output_ids.iter().enumerate() {
            if i >= m.psbt.inputs.len() {
                // Pure MWEB txs often have empty transparent vin; store ids on global unknown.
                let key = raw::Key {
                    type_value: MWEB_SPENT_OUTPUT_ID_TYPE,
                    key: (i as u32).to_le_bytes().to_vec(),
                };
                m.psbt.unknown.insert(key, coin_id.to_vec());
                continue;
            }
            let inp = MwebPsbtInput {
                output_id: Some(*coin_id),
                ..MwebPsbtInput::default()
            };
            for (k, v) in inp.to_unknown_map() {
                m.psbt.inputs[i].unknown.insert(k, v);
            }
        }
        Ok(m)
    }

    /// Populate from a peg-in PSBT + authored body ([`FinishedMwebPegin`]).
    pub fn from_pegin_psbt(psbt: Psbt, pegin: &FinishedMwebPegin) -> Result<Self, Error> {
        let mut m = Self::from_psbt(psbt);
        m.mw_tx = Some(pegin.mw_tx.clone());
        m.tx_offset = Some(pegin.mw_tx.kernel_offset);
        m.stealth_offset = Some(pegin.mw_tx.stealth_offset);
        m.kernels = pegin
            .mw_tx
            .body
            .kernels
            .iter()
            .map(MwebPsbtKernel::from_kernel)
            .collect();
        m.apply_unknown_maps();
        Ok(m)
    }

    /// Extract network transaction with `mw_tx` set (replaces post-hoc `attach_mweb_tx` when complete).
    pub fn extract_tx_with_mweb(&self) -> Result<Transaction, Error> {
        let mw = self
            .mw_tx
            .clone()
            .ok_or_else(|| Error::Crypto("MwebPsbt missing mw_tx; cannot extract".into()))?;
        let mut tx = self
            .psbt
            .clone()
            .extract_tx()
            .map_err(|e| Error::Crypto(format!("extract_tx: {e}")))?;
        tx.mw_tx = Some(mw);
        Ok(tx)
    }

    /// True when MWEB globals + body are present.
    pub fn is_mweb_complete(&self) -> bool {
        self.mw_tx.is_some() && self.tx_offset.is_some() && self.stealth_offset.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_map_roundtrip_unknown() {
        let inp = MwebPsbtInput {
            output_id: Some([9u8; 32]),
            commit: Some({
                let mut c = [0u8; 33];
                c[0] = 2;
                c
            }),
            amount: Some(50_000),
            address_index: Some(2),
            features: Some(1),
            ..MwebPsbtInput::default()
        };
        let map = inp.to_unknown_map();
        let back = MwebPsbtInput::from_unknown_map(&map);
        assert_eq!(back.output_id, inp.output_id);
        assert_eq!(back.commit, inp.commit);
        assert_eq!(back.amount, inp.amount);
        assert_eq!(back.address_index, inp.address_index);
        assert_eq!(back.features, inp.features);
    }

    #[test]
    fn type_codes_match_ltcd() {
        assert_eq!(MWEB_TX_OFFSET_TYPE, 0x90);
        assert_eq!(MWEB_TX_STEALTH_OFFSET_TYPE, 0x91);
        assert_eq!(MWEB_KERNEL_COUNT_TYPE, 0x92);
        assert_eq!(MWEB_SPENT_OUTPUT_ID_TYPE, 0x90);
        assert_eq!(MWEB_STEALTH_ADDRESS_OUTPUT_TYPE, 0x90);
        assert_eq!(MWEB_KERNEL_EXCESS_COMMIT_TYPE, 0);
        assert_eq!(MWEB_KERNEL_SIGNATURE_TYPE, 8);
    }

    #[test]
    fn kernel_pairs_include_fee() {
        let k = MwebPsbtKernel {
            excess_commit: Some([2u8; 33]),
            fee: Some(1000),
            features: Some(0),
            ..MwebPsbtKernel::default()
        };
        let pairs = k.to_pairs();
        assert!(pairs.iter().any(|(t, _)| *t == MWEB_KERNEL_FEE_TYPE));
        assert!(pairs
            .iter()
            .any(|(t, _)| *t == MWEB_KERNEL_EXCESS_COMMIT_TYPE));
    }
}
