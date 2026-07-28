//! ltcsuite-compatible PSBTv2 MWEB key types and maps.
//!
//! Key codes match [`ltcsuite/ltcd` `ltcutil/psbt/types.go`](https://github.com/ltcsuite/ltcd/blob/master/ltcutil/psbt/types.go)
//! (first-class `0x90+` types — not BIP174 `0xFC` proprietary blobs).
//!
//! Lives in `bdk_mweb` until the published `litecoin` crate grows native PSBTv2 + MWEB maps.
//! Values serialize into [`bitcoin::psbt::Psbt`] `unknown` maps plus a parallel kernel list.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::blockdata::mimblewimble::{
    Input, Kernel, Output, Transaction as MwebTransaction,
};
use bitcoin::consensus::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::psbt::{raw, Psbt};
use bitcoin::secp256k1::{All, PublicKey};
use bitcoin::Transaction;

use crate::coin_db::MwebCoin;
use crate::crypto::random_secret;
use crate::error::Error;
use crate::tx_builder::{create_input, FinishedMwebPegin, FinishedMwebTx};

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

    /// Build typed fields from a wire [`Input`].
    pub fn from_mweb_input(input: &Input) -> Self {
        Self {
            output_id: Some(input.output_id),
            commit: Some(input.commitment),
            output_pubkey: Some(input.output_public_key.serialize().to_vec()),
            input_pubkey: input
                .input_public_key
                .map(|pk| pk.serialize().to_vec()),
            features: Some(input.features),
            signature: Some(input.signature.to_vec()),
            extra_data: if input.extra_data.is_empty() {
                None
            } else {
                Some(input.extra_data.clone())
            },
            ..Self::default()
        }
    }

    /// Fill wallet-known secrets / metadata from an owned [`MwebCoin`].
    pub fn enrich_from_coin(&mut self, coin: &MwebCoin) {
        self.amount = Some(coin.amount);
        self.address_index = Some(coin.address_index);
        self.shared_secret = Some(coin.shared_secret);
        if self.commit.is_none() {
            self.commit = Some(coin.commitment);
        }
        if self.output_id.is_none() {
            self.output_id = Some(coin.output_id);
        }
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

/// Transparent [`Psbt`] plus MWEB global offsets and typed maps (ltcd-shaped).
///
/// Pure MWEB spends often have empty transparent `vin`/`vout`; input/output maps then live in
/// [`Self::mweb_inputs`] / [`Self::mweb_outputs`] (parallel to [`Self::kernels`]) and are also
/// mirrored into `psbt.unknown` / per-input `unknown` when slots exist.
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
    /// MWEB input maps (ltcd `PInput` MWEB subset), ordered like `mw_tx.body.inputs`.
    pub mweb_inputs: Vec<MwebPsbtInput>,
    /// MWEB output maps (ltcd `POutput` MWEB subset), ordered like `mw_tx.body.outputs`.
    pub mweb_outputs: Vec<MwebPsbtOutput>,
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
            mweb_inputs: Vec::new(),
            mweb_outputs: Vec::new(),
            mw_tx: None,
        }
    }

    /// Inject MWEB globals into `psbt.unknown` and mirror input/output maps into PSBT slots.
    ///
    /// Kernel field pairs stay on [`Self::kernels`] (ltcd `PKernel` list) until upstream PSBTv2
    /// lands in the `litecoin` crate. Pure MWEB spends with empty `vin` keep maps on
    /// [`Self::mweb_inputs`] / [`Self::mweb_outputs`] and record spent `output_id`s in global unknown.
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

        for (i, inp) in self.mweb_inputs.iter().enumerate() {
            if i < self.psbt.inputs.len() {
                for (k, v) in inp.to_unknown_map() {
                    self.psbt.inputs[i].unknown.insert(k, v);
                }
            } else if let Some(id) = inp.output_id {
                let key = raw::Key {
                    type_value: MWEB_SPENT_OUTPUT_ID_TYPE,
                    key: (i as u32).to_le_bytes().to_vec(),
                };
                self.psbt.unknown.insert(key, id.to_vec());
            }
        }

        for (i, out) in self.mweb_outputs.iter().enumerate() {
            if i < self.psbt.outputs.len() {
                for (k, v) in out.to_unknown_map() {
                    self.psbt.outputs[i].unknown.insert(k, v);
                }
            }
        }
    }

    /// Populate typed maps from an assembled MWEB body (used by fund→sign and extract helpers).
    pub fn populate_maps_from_mw(&mut self, mw: &MwebTransaction, coins: &[MwebCoin]) {
        self.tx_offset = Some(mw.kernel_offset);
        self.stealth_offset = Some(mw.stealth_offset);
        self.kernels = mw.body.kernels.iter().map(MwebPsbtKernel::from_kernel).collect();
        self.mweb_outputs = mw
            .body
            .outputs
            .iter()
            .map(MwebPsbtOutput::from_mweb_output)
            .collect();
        self.mweb_inputs = mw
            .body
            .inputs
            .iter()
            .map(|inp| {
                let mut mapped = MwebPsbtInput::from_mweb_input(inp);
                if let Some(coin) = coins.iter().find(|c| c.output_id == inp.output_id) {
                    mapped.enrich_from_coin(coin);
                }
                mapped
            })
            .collect();
    }

    /// Alias for callers that treat map population as the public native-PSBT API.
    pub fn populate_maps_from_mw_public(&mut self, mw: &MwebTransaction, coins: &[MwebCoin]) {
        self.populate_maps_from_mw(mw, coins);
    }

    /// Scrub wallet secrets from maps before extract/broadcast (ltcd finalize hygiene).
    ///
    /// Removes amount / shared secret / address index from inputs. Keeps wire fields needed
    /// to assemble `mw_tx` (commitments, pubkeys, signatures, rangeproofs, stealth address).
    pub fn scrub_sensitive_fields(&mut self) {
        for inp in &mut self.mweb_inputs {
            inp.amount = None;
            inp.shared_secret = None;
            inp.address_index = None;
            inp.key_exchange_pubkey = None;
        }
        self.apply_unknown_maps();
    }

    fn from_mw_body(mut unsigned: Transaction, mw: MwebTransaction) -> Result<Self, Error> {
        unsigned.mw_tx = None;
        let psbt = Psbt::from_unsigned_tx(unsigned)
            .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;
        let mut m = Self::from_psbt(psbt);
        m.populate_maps_from_mw(&mw, &[]);
        m.mw_tx = Some(mw);
        m.apply_unknown_maps();
        Ok(m)
    }

    /// Populate from a finished MWEB spend / peg-out ([`FinishedMwebTx`]).
    ///
    /// Fills input/output/kernel maps from the authored body and enriches inputs from
    /// [`FinishedMwebTx::spent_coins`]. Happy-path extract uses [`Self::extract_tx_with_mweb`].
    pub fn from_finished_mweb_tx(finished: &FinishedMwebTx) -> Result<Self, Error> {
        let mw = finished
            .tx
            .mw_tx
            .clone()
            .ok_or_else(|| Error::Crypto("FinishedMwebTx missing mw_tx".into()))?;
        let mut m = Self::from_mw_body(finished.tx.clone(), mw)?;
        let body = m
            .mw_tx
            .clone()
            .expect("mw_tx set by from_mw_body");
        m.populate_maps_from_mw(&body, &finished.spent_coins);
        m.apply_unknown_maps();
        Ok(m)
    }

    /// Populate from a peg-in PSBT + authored body ([`FinishedMwebPegin`]).
    pub fn from_pegin_psbt(psbt: Psbt, pegin: &FinishedMwebPegin) -> Result<Self, Error> {
        let mut m = Self::from_psbt(psbt);
        m.populate_maps_from_mw(&pegin.mw_tx, &[]);
        m.mw_tx = Some(pegin.mw_tx.clone());
        m.apply_unknown_maps();
        Ok(m)
    }

    /// ltcwallet-shaped finalize: enrich input maps from `coins`, (re)sign any unsigned MWEB
    /// inputs that have spend keys, and ensure [`Self::mw_tx`] is ready for extract.
    ///
    /// When `mw_tx` is already fully authored (BDK `MwebTxBuilder` path), this syncs maps from the
    /// body and fills amount / shared secret / address index from `coins`. When an input map has
    /// secrets but lacks a signature, a new input signature is created via [`create_input`] and
    /// written back into `mw_tx` (kernel offsets must already be consistent).
    pub fn sign_mweb_components(
        &mut self,
        coins: &[MwebCoin],
        secp: &Secp256k1<All>,
    ) -> Result<(), Error> {
        if let Some(mw) = self.mw_tx.clone() {
            self.populate_maps_from_mw(&mw, coins);
            // Fill missing input signatures from coin spend keys (rare on BDK author path).
            let mut body_inputs = mw.body.inputs.clone();
            let mut mutated = false;
            for (i, mapped) in self.mweb_inputs.iter_mut().enumerate() {
                if mapped.signature.is_some() {
                    continue;
                }
                let id = mapped
                    .output_id
                    .ok_or_else(|| Error::Crypto("unsigned MWEB input missing output_id".into()))?;
                let coin = coins
                    .iter()
                    .find(|c| c.output_id == id)
                    .ok_or_else(|| Error::Crypto("unsigned MWEB input missing coin secrets".into()))?;
                let spend_key = coin
                    .spend_key
                    .ok_or(Error::MissingCoinSecrets)?;
                let ephemeral = random_secret(secp);
                let input = create_input(&id, &coin.commitment, &ephemeral, &spend_key, secp)?;
                *mapped = MwebPsbtInput::from_mweb_input(&input);
                mapped.enrich_from_coin(coin);
                if i < body_inputs.len() {
                    body_inputs[i] = input;
                    mutated = true;
                }
            }
            if mutated {
                let mut mw = mw;
                mw.body.inputs = body_inputs;
                self.mw_tx = Some(mw);
            }
            self.apply_unknown_maps();
            return Ok(());
        }

        // No authored body: require maps complete enough to rebuild wire inputs/outputs/kernels.
        let mw = self.assemble_mw_tx_from_maps()?;
        self.mw_tx = Some(mw);
        self.apply_unknown_maps();
        Ok(())
    }

    fn assemble_mw_tx_from_maps(&self) -> Result<MwebTransaction, Error> {
        let kernel_offset = self
            .tx_offset
            .ok_or_else(|| Error::Crypto("missing tx_offset".into()))?;
        let stealth_offset = self
            .stealth_offset
            .ok_or_else(|| Error::Crypto("missing stealth_offset".into()))?;

        let mut inputs = Vec::with_capacity(self.mweb_inputs.len());
        for inp in &self.mweb_inputs {
            inputs.push(wire_input_from_map(inp)?);
        }
        let mut outputs = Vec::with_capacity(self.mweb_outputs.len());
        for out in &self.mweb_outputs {
            outputs.push(wire_output_from_map(out)?);
        }
        let mut kernels = Vec::with_capacity(self.kernels.len());
        for k in &self.kernels {
            kernels.push(wire_kernel_from_map(k)?);
        }
        Ok(MwebTransaction {
            kernel_offset,
            stealth_offset,
            body: bitcoin::blockdata::mimblewimble::TxBody {
                inputs,
                outputs,
                kernels,
            },
        })
    }

    /// Extract network transaction with `mw_tx` set (replaces post-hoc `attach_mweb_tx` when complete).
    ///
    /// Prefer maps as source of truth: if `mw_tx` is unset, assemble from signed maps.
    pub fn extract_tx_with_mweb(&self) -> Result<Transaction, Error> {
        let mw = match &self.mw_tx {
            Some(mw) => mw.clone(),
            None => self.assemble_mw_tx_from_maps()?,
        };
        let mut tx = self
            .psbt
            .clone()
            .extract_tx()
            .map_err(|e| Error::Crypto(format!("extract_tx: {e}")))?;
        tx.mw_tx = Some(mw);
        Ok(tx)
    }

    /// True when MWEB globals are set and a body can be assembled (maps or cached `mw_tx`).
    pub fn is_mweb_complete(&self) -> bool {
        self.tx_offset.is_some()
            && self.stealth_offset.is_some()
            && (self.mw_tx.is_some()
                || (!self.mweb_inputs.is_empty()
                    || !self.mweb_outputs.is_empty()
                    || !self.kernels.is_empty()))
    }
}

fn wire_input_from_map(inp: &MwebPsbtInput) -> Result<Input, Error> {
    let output_id = inp
        .output_id
        .ok_or_else(|| Error::Crypto("input map missing output_id".into()))?;
    let commitment = inp
        .commit
        .ok_or_else(|| Error::Crypto("input map missing commit".into()))?;
    let features = inp.features.unwrap_or(0);
    let output_public_key = PublicKey::from_slice(
        inp.output_pubkey
            .as_ref()
            .ok_or_else(|| Error::Crypto("input map missing output_pubkey".into()))?,
    )?;
    let input_public_key = match &inp.input_pubkey {
        Some(b) => Some(PublicKey::from_slice(b)?),
        None => None,
    };
    let mut signature = [0u8; 64];
    let sig = inp
        .signature
        .as_ref()
        .ok_or_else(|| Error::Crypto("input map missing signature".into()))?;
    if sig.len() != 64 {
        return Err(Error::Crypto("input signature must be 64 bytes".into()));
    }
    signature.copy_from_slice(sig);
    Ok(Input {
        features,
        output_id,
        commitment,
        input_public_key,
        output_public_key,
        extra_data: inp.extra_data.clone().unwrap_or_default(),
        signature,
    })
}

fn wire_output_from_map(out: &MwebPsbtOutput) -> Result<Output, Error> {
    use bitcoin::blockdata::mimblewimble::{OutputMessage, OutputMessageStandardFields};

    let commitment = out
        .commit
        .ok_or_else(|| Error::Crypto("output map missing commit".into()))?;
    let sender_public_key = PublicKey::from_slice(
        out.sender_pubkey
            .as_ref()
            .ok_or_else(|| Error::Crypto("output map missing sender_pubkey".into()))?,
    )?;
    let receiver_public_key = PublicKey::from_slice(
        out.output_pubkey
            .as_ref()
            .ok_or_else(|| Error::Crypto("output map missing output_pubkey".into()))?,
    )?;
    let features = out.features.unwrap_or(0);
    let standard_fields = match &out.standard_fields {
        Some(blob) if blob.len() >= 33 + 1 + 8 + 16 => {
            let ke = PublicKey::from_slice(&blob[..33])?;
            let view_tag = blob[33];
            let masked_value = u64::from_le_bytes(blob[34..42].try_into().unwrap());
            let mut masked_nonce = [0u8; 16];
            masked_nonce.copy_from_slice(&blob[42..58]);
            Some(OutputMessageStandardFields {
                key_exchange_pubkey: ke,
                view_tag,
                masked_value,
                masked_nonce,
            })
        }
        _ => None,
    };
    let mut range_proof = [0u8; 675];
    let rp = out
        .range_proof
        .as_ref()
        .ok_or_else(|| Error::Crypto("output map missing range_proof".into()))?;
    if rp.len() != 675 {
        return Err(Error::Crypto("range_proof must be 675 bytes".into()));
    }
    range_proof.copy_from_slice(rp);
    let mut signature = [0u8; 64];
    let sig = out
        .signature
        .as_ref()
        .ok_or_else(|| Error::Crypto("output map missing signature".into()))?;
    if sig.len() != 64 {
        return Err(Error::Crypto("output signature must be 64 bytes".into()));
    }
    signature.copy_from_slice(sig);
    Ok(Output {
        commitment,
        sender_public_key,
        receiver_public_key,
        message: OutputMessage {
            features,
            standard_fields,
            extra_data: out.extra_data.clone().unwrap_or_default(),
        },
        range_proof,
        signature,
    })
}

fn wire_kernel_from_map(k: &MwebPsbtKernel) -> Result<Kernel, Error> {
    use bitcoin::blockdata::mimblewimble::PegOutCoin;
    use bitcoin::consensus::deserialize;

    let excess = k
        .excess_commit
        .ok_or_else(|| Error::Crypto("kernel map missing excess".into()))?;
    let signature = k
        .signature
        .ok_or_else(|| Error::Crypto("kernel map missing signature".into()))?;
    let pegouts: Vec<PegOutCoin> = match &k.pegout {
        Some(raw) => deserialize(raw)
            .map_err(|e| Error::Crypto(format!("kernel pegout decode: {e}")))?,
        None => Vec::new(),
    };
    let stealth_excess = match &k.stealth_commit {
        Some(b) => Some(PublicKey::from_slice(b)?),
        None => None,
    };
    Ok(Kernel {
        features: k.features.unwrap_or(0),
        fee: k.fee.map(|f| f as i64),
        pegin: k.pegin_amount.map(|a| a as i64),
        pegouts,
        lock_height: k.lock_height,
        stealth_excess,
        extra_data: k.extra_data.clone().unwrap_or_default(),
        excess,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{MasterKeyScheme, MasterKeys};
    use crate::tx_builder::MwebTxBuilder;
    use bitcoin::{Network, NetworkKind};

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

    #[test]
    fn finished_mweb_tx_maps_roundtrip_and_extract() {
        let secp = Secp256k1::new();
        let seed = [7u8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let recv = keys.address(1, NetworkKind::Test, &secp).unwrap();

        // Build a peg-in then spend it so we have a real FinishedMwebTx with signed maps.
        let pegin = crate::build_pegin(&keys, 1, 1_000_000, 50_000, NetworkKind::Test, &secp)
            .unwrap();
        let coin = pegin.outputs[0].clone();
        let send_amt = coin.amount - 50_000;
        let finished = MwebTxBuilder::new()
            .add_input(coin.clone())
            .add_recipient(recv, send_amt)
            .fee(50_000)
            .finish(&keys, 0, NetworkKind::Test, &secp)
            .unwrap();

        let mut mweb_psbt = MwebPsbt::from_finished_mweb_tx(&finished).unwrap();
        assert!(!mweb_psbt.mweb_inputs.is_empty());
        assert!(!mweb_psbt.mweb_outputs.is_empty());
        assert!(!mweb_psbt.kernels.is_empty());
        assert_eq!(mweb_psbt.mweb_inputs[0].amount, Some(coin.amount));
        assert_eq!(mweb_psbt.mweb_inputs[0].shared_secret, Some(coin.shared_secret));
        assert!(mweb_psbt.mweb_inputs[0].signature.is_some());
        assert!(mweb_psbt.mweb_outputs[0].range_proof.is_some());
        assert!(mweb_psbt.kernels[0].signature.is_some());

        mweb_psbt
            .sign_mweb_components(&finished.spent_coins, &secp)
            .unwrap();
        let tx = mweb_psbt.extract_tx_with_mweb().unwrap();
        assert!(tx.mw_tx.is_some());
        assert_eq!(
            tx.mw_tx.as_ref().unwrap().body.inputs[0].output_id,
            coin.output_id
        );

        // Assemble-from-maps path: drop mw_tx and rebuild.
        let mut maps_only = mweb_psbt.clone();
        maps_only.mw_tx = None;
        maps_only.sign_mweb_components(&finished.spent_coins, &secp).unwrap();
        let rebuilt = maps_only.extract_tx_with_mweb().unwrap();
        assert_eq!(
            rebuilt.mw_tx.as_ref().unwrap().kernel_offset,
            finished.tx.mw_tx.as_ref().unwrap().kernel_offset
        );
    }

    #[test]
    fn fund_sign_extract_emits_stealth_and_scrubs() {
        use crate::psbt_fund::{fund_mweb_spend, sign_funded_mweb};
        use crate::keys::{MasterKeyScheme, MasterKeys};
        use crate::tx_builder::build_pegin;
        use bitcoin::{Network, NetworkKind};

        let secp = Secp256k1::new();
        let seed = [11u8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let pegin = build_pegin(&keys, 1, 1_000_000, 50_000, NetworkKind::Test, &secp).unwrap();
        let coin = pegin.outputs[0].clone();
        let recv = keys.address(2, NetworkKind::Test, &secp).unwrap();
        let send_amt = coin.amount - 50_000;

        let mut funded = fund_mweb_spend(
            vec![coin.clone()],
            vec![(recv, send_amt)],
            vec![],
            50_000,
            &keys,
            0,
            NetworkKind::Test,
            &secp,
        )
        .unwrap();
        assert!(funded.mweb.mw_tx.is_none());
        assert!(funded.mweb.mweb_outputs[0].stealth_address.as_ref().unwrap().len() == 66);
        assert!(funded.mweb.mweb_inputs[0].signature.is_none());

        sign_funded_mweb(&mut funded, &keys, &secp).unwrap();
        assert!(funded.mweb.mw_tx.is_none(), "mw_tx only at extract");
        assert!(funded.mweb.mweb_inputs[0].signature.is_some());
        // Scrubbed secrets
        assert!(funded.mweb.mweb_inputs[0].amount.is_none());
        assert!(funded.mweb.mweb_inputs[0].shared_secret.is_none());
        // Stealth address retained for ltcd finalize parity
        assert!(funded.mweb.mweb_outputs.iter().any(|o| o.stealth_address.is_some()));

        let tx = funded.mweb.extract_tx_with_mweb().unwrap();
        assert!(tx.mw_tx.is_some());
        assert_eq!(tx.mw_tx.as_ref().unwrap().body.inputs[0].output_id, coin.output_id);
    }
}
