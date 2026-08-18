//! Wallet-facing helpers over native [`bitcoin::psbt::mweb`] types (litecoin 0.32.8-rc.2+).
//!
//! Typed `0x90+` maps live in the `litecoin` crate. This module keeps BDK-only fund/sign/scrub
//! adapters and conversion helpers between wire MimbleWimble types and PSBT maps.

use alloc::vec::Vec;

use bitcoin::blockdata::mimblewimble::{
    self as mw, Input, Kernel, Output, Transaction as MwebTransaction,
};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::mweb::{self as native, MwebInput, MwebKernel, MwebOutput};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::All;
use bitcoin::Transaction;

use crate::coin_db::MwebCoin;
use crate::crypto::random_secret;
use crate::error::Error;
use crate::tx_builder::{create_input, FinishedMwebPegin, FinishedMwebTx};

pub use bitcoin::psbt::mweb::{
    MwebInput as MwebPsbtInput, MwebKernel as MwebPsbtKernel, MwebOutput as MwebPsbtOutput,
    MWEB_KERNEL_COUNT_TYPE, MWEB_KERNEL_EXCESS_COMMIT_TYPE, MWEB_KERNEL_FEE_TYPE,
    MWEB_KERNEL_SIGNATURE_TYPE, MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE,
    MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE, MWEB_SPENT_OUTPUT_ID_TYPE, MWEB_STEALTH_ADDRESS_OUTPUT_TYPE,
    MWEB_TX_OFFSET_TYPE, MWEB_TX_STEALTH_OFFSET_TYPE,
};

/// Fill wallet-known secrets / metadata from an owned [`MwebCoin`].
pub fn enrich_input_from_coin(inp: &mut MwebInput, coin: &MwebCoin) {
    inp.amount = Some(coin.amount);
    inp.address_index = Some(coin.address_index);
    inp.shared_secret = Some(coin.shared_secret);
    if inp.commit.is_none() {
        inp.commit = Some(coin.commitment);
    }
    if inp.output_id.is_none() {
        inp.output_id = Some(coin.output_id);
    }
}

/// Build typed PSBT input fields from a wire [`Input`].
pub fn mweb_input_from_wire(input: &Input) -> MwebInput {
    MwebInput {
        output_id: Some(input.output_id),
        commit: Some(input.commitment),
        output_pubkey: Some(input.output_public_key.serialize().to_vec()),
        input_pubkey: input.input_public_key.map(|pk| pk.serialize().to_vec()),
        features: Some(input.features),
        signature: Some(input.signature.to_vec()),
        extra_data: if input.extra_data.is_empty() {
            None
        } else {
            Some(input.extra_data.clone())
        },
        ..MwebInput::default()
    }
}

/// Build typed PSBT output fields from a wire [`Output`].
pub fn mweb_output_from_wire(output: &Output) -> MwebOutput {
    MwebOutput {
        commit: Some(output.commitment),
        output_pubkey: Some(output.receiver_public_key.serialize().to_vec()),
        sender_pubkey: Some(output.sender_public_key.serialize().to_vec()),
        features: Some(output.message.features),
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
        amount: None,
    }
}

/// Build typed PSBT kernel fields from a wire [`Kernel`].
pub fn mweb_kernel_from_wire(k: &Kernel) -> MwebKernel {
    MwebKernel {
        excess_commit: Some(k.excess),
        stealth_commit: k.stealth_excess.map(|pk| pk.serialize().to_vec()),
        fee: k.fee.map(|f| f as u64),
        pegin_amount: k.pegin.map(|a| a as u64),
        pegouts: k.pegouts.iter().map(native::pegout_psbt_value).collect(),
        lock_height: k.lock_height,
        features: Some(k.features),
        extra_data: if k.extra_data.is_empty() {
            None
        } else {
            Some(k.extra_data.clone())
        },
        signature: Some(k.signature),
        unknowns: Vec::new(),
    }
}

/// Populate native PSBT MWEB maps from an assembled MimbleWimble body.
pub fn populate_psbt_from_mw(psbt: &mut Psbt, mw: &MwebTransaction, coins: &[MwebCoin]) {
    psbt.mweb_tx_offset = Some(mw.kernel_offset);
    psbt.mweb_stealth_offset = Some(mw.stealth_offset);
    psbt.mweb_kernels = mw.body.kernels.iter().map(mweb_kernel_from_wire).collect();
    psbt.mweb_outputs = mw.body.outputs.iter().map(mweb_output_from_wire).collect();
    psbt.mweb_inputs = mw
        .body
        .inputs
        .iter()
        .map(|inp| {
            let mut mapped = mweb_input_from_wire(inp);
            if let Some(coin) = coins.iter().find(|c| c.output_id == inp.output_id) {
                enrich_input_from_coin(&mut mapped, coin);
            }
            mapped
        })
        .collect();
}

/// LIP-0007 single-index updater descriptor: `mweb([fp/scan]WIF,[fp/spend]PUB,i)`.
///
/// Scan is a private KEY (WIF). Spend is the master spend compressed pubkey (watch form).
/// Matches Core v24 `doc/mweb/mweb-descriptors.md` + live `walletcreatefundedpsbt`.
pub fn mweb_address_descriptor(
    keys: &crate::keys::MasterKeys,
    index: u32,
    secp: &Secp256k1<All>,
) -> alloc::string::String {
    let scan_wif = bitcoin::key::PrivateKey::new(keys.scan, keys.network).to_wif();
    let spend_hex = keys.spend_public(secp).to_string();
    alloc::format!(
        "mweb([{}{}]{},[{}{}]{},{})",
        keys.master_fingerprint,
        keys.scan_path,
        scan_wif,
        keys.master_fingerprint,
        keys.spend_path,
        spend_hex,
        index
    )
}

/// Updater: attach LIP-0007 `mweb()` descriptors. Does **not** emit reserved `0x9A`/`0x9B`.
///
/// `address_index` stays on the map for wallet-internal coin enrichment; rust-litecoin
/// does not serialize it as `0x96`.
pub fn populate_mweb_key_origins(
    psbt: &mut Psbt,
    keys: &crate::keys::MasterKeys,
    secp: &Secp256k1<All>,
) {
    for inp in &mut psbt.mweb_inputs {
        inp.master_scan_key_origin = None;
        inp.master_spend_key_origin = None;
        if let Some(idx) = inp.address_index {
            inp.address_descriptor = Some(mweb_address_descriptor(keys, idx, secp));
        }
    }
    for inp in &mut psbt.inputs {
        inp.mweb.master_scan_key_origin = None;
        inp.mweb.master_spend_key_origin = None;
        if let Some(idx) = inp.mweb.address_index {
            inp.mweb.address_descriptor = Some(mweb_address_descriptor(keys, idx, secp));
        }
    }
}

/// Validate that each MWEB spend input has an ASCII `mweb(` descriptor (LIP-0007 updater).
pub fn validate_mweb_key_origins(psbt: &Psbt) -> Result<(), Error> {
    for inp in &psbt.mweb_inputs {
        if inp.output_id.is_none() {
            continue;
        }
        match inp.address_descriptor.as_deref() {
            Some(d) if d.starts_with("mweb(") => {}
            _ => {
                return Err(Error::Crypto(
                    "incomplete MWEB address descriptor (need ASCII mweb(...))".into(),
                ))
            }
        }
    }
    Ok(())
}

/// Validate descriptors match this wallet's fingerprint + scan/spend paths.
pub fn validate_mweb_key_origins_against(
    psbt: &Psbt,
    keys: &crate::keys::MasterKeys,
) -> Result<(), Error> {
    validate_mweb_key_origins(psbt)?;
    let fp = alloc::format!("{}", keys.master_fingerprint);
    let scan = alloc::format!("{}", keys.scan_path);
    let spend = alloc::format!("{}", keys.spend_path);
    for inp in &psbt.mweb_inputs {
        if inp.output_id.is_none() {
            continue;
        }
        let desc = inp.address_descriptor.as_deref().unwrap_or("");
        if !desc.contains(&fp) || !desc.contains(&scan) || !desc.contains(&spend) {
            return Err(Error::Crypto(
                "MWEB address descriptor fingerprint/path mismatch".into(),
            ));
        }
        if let Some(idx) = inp.address_index {
            let tail = alloc::format!(",{idx})");
            if !desc.ends_with(&tail) {
                return Err(Error::Crypto(
                    "MWEB address descriptor index mismatch".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Scrub wallet secrets from maps before extract/broadcast.
///
/// Removes amount / shared secret / address index / key-exchange / the `mweb()`
/// descriptor (scan WIF). Wire fields needed to assemble `mw_tx` stay.
pub fn scrub_sensitive_fields(psbt: &mut Psbt) {
    for inp in &mut psbt.mweb_inputs {
        inp.amount = None;
        inp.shared_secret = None;
        inp.address_index = None;
        inp.address_descriptor = None;
        inp.key_exchange_pubkey = None;
    }
    for inp in &mut psbt.inputs {
        inp.mweb.amount = None;
        inp.mweb.shared_secret = None;
        inp.mweb.address_index = None;
        inp.mweb.address_descriptor = None;
        inp.mweb.key_exchange_pubkey = None;
    }
}

/// Populate a PSBT from a finished MWEB spend / peg-out ([`FinishedMwebTx`]).
pub fn psbt_from_finished_mweb_tx(finished: &FinishedMwebTx) -> Result<Psbt, Error> {
    let mw = finished
        .tx
        .mw_tx
        .clone()
        .ok_or_else(|| Error::Crypto("FinishedMwebTx missing mw_tx".into()))?;
    let mut unsigned = finished.tx.clone();
    unsigned.mw_tx = None;
    let mut psbt = Psbt::from_unsigned_tx(unsigned)
        .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;
    populate_psbt_from_mw(&mut psbt, &mw, &finished.spent_coins);
    Ok(psbt)
}

/// Populate MWEB maps on a peg-in PSBT from an authored body ([`FinishedMwebPegin`]).
pub fn populate_pegin_psbt(psbt: &mut Psbt, pegin: &FinishedMwebPegin) {
    populate_psbt_from_mw(psbt, &pegin.mw_tx, &[]);
}

/// ltcwallet-shaped finalize helper: enrich / (re)sign MWEB input maps that lack signatures.
///
/// Prefer [`crate::psbt_fund::sign_funded_mweb`] for the happy-path fund→sign lifecycle. This
/// helper covers peg-in extract and legacy [`FinishedMwebTx`] paths where maps already carry a
/// signed body and only need sync / extract readiness.
pub fn sign_mweb_components(
    psbt: &mut Psbt,
    coins: &[MwebCoin],
    secp: &Secp256k1<All>,
) -> Result<(), Error> {
    // Prefer parallel mweb_inputs (pure MWEB); fall back to per-slot Input::mweb.
    if psbt.mweb_inputs.is_empty() && psbt.inputs.iter().any(|i| i.mweb.output_id.is_some()) {
        psbt.mweb_inputs = psbt.inputs.iter().map(|i| i.mweb.clone()).collect();
    }
    if psbt.mweb_outputs.is_empty() && psbt.outputs.iter().any(|o| o.mweb.commit.is_some()) {
        psbt.mweb_outputs = psbt.outputs.iter().map(|o| o.mweb.clone()).collect();
    }

    for mapped in &mut psbt.mweb_inputs {
        let id = match mapped.output_id {
            Some(id) => id,
            None => continue,
        };
        if let Some(coin) = coins.iter().find(|c| c.output_id == id) {
            enrich_input_from_coin(mapped, coin);
        }
        if mapped.signature.is_some() {
            continue;
        }
        let coin = coins
            .iter()
            .find(|c| c.output_id == id)
            .ok_or_else(|| Error::Crypto("unsigned MWEB input missing coin secrets".into()))?;
        let spend_key = coin.spend_key.ok_or(Error::MissingCoinSecrets)?;
        let ephemeral = random_secret(secp);
        let input = create_input(&id, &coin.commitment, &ephemeral, &spend_key, secp)?;
        *mapped = mweb_input_from_wire(&input);
        enrich_input_from_coin(mapped, coin);
    }

    // Ensure offsets exist when kernels already carry signatures (legacy authored body path).
    if psbt.mweb_tx_offset.is_none() || psbt.mweb_stealth_offset.is_none() {
        return Err(Error::Crypto(
            "MWEB PSBT missing tx/stealth offset; use fund→sign or populate from mw_tx".into(),
        ));
    }
    Ok(())
}

/// Extract a network [`Transaction`] with `mw_tx` via native [`Psbt::extract_tx_with_mweb`].
pub fn extract_tx_with_mweb(psbt: &Psbt) -> Result<Transaction, Error> {
    psbt.extract_tx_with_mweb()
        .map_err(|e| Error::Crypto(format!("extract_tx_with_mweb: {e}")))
}

/// True when native MWEB globals are set and maps can form a body.
pub fn is_mweb_complete(psbt: &Psbt) -> bool {
    psbt.mweb_tx_offset.is_some()
        && psbt.mweb_stealth_offset.is_some()
        && (!psbt.mweb_inputs.is_empty()
            || !psbt.mweb_outputs.is_empty()
            || !psbt.mweb_kernels.is_empty())
}

/// Thin compatibility wrapper around native [`Psbt`] MWEB fields (migration aid).
///
/// New code should use [`Psbt`] directly with [`scrub_sensitive_fields`] /
/// [`extract_tx_with_mweb`].
#[derive(Debug, Clone)]
#[deprecated(note = "use bitcoin::psbt::Psbt mweb_* fields directly")]
pub struct MwebPsbt {
    /// Underlying PSBT with native MWEB maps.
    pub psbt: Psbt,
}

#[allow(deprecated)]
impl MwebPsbt {
    /// Wrap a PSBT.
    pub fn from_psbt(psbt: Psbt) -> Self {
        Self { psbt }
    }

    /// Populate from a finished MWEB spend.
    pub fn from_finished_mweb_tx(finished: &FinishedMwebTx) -> Result<Self, Error> {
        Ok(Self {
            psbt: psbt_from_finished_mweb_tx(finished)?,
        })
    }

    /// Populate from a peg-in PSBT + authored body.
    pub fn from_pegin_psbt(psbt: Psbt, pegin: &FinishedMwebPegin) -> Result<Self, Error> {
        let mut p = psbt;
        populate_pegin_psbt(&mut p, pegin);
        Ok(Self { psbt: p })
    }

    /// Sign / enrich components.
    pub fn sign_mweb_components(
        &mut self,
        coins: &[MwebCoin],
        secp: &Secp256k1<All>,
    ) -> Result<(), Error> {
        sign_mweb_components(&mut self.psbt, coins, secp)
    }

    /// Scrub secrets.
    pub fn scrub_sensitive_fields(&mut self) {
        scrub_sensitive_fields(&mut self.psbt);
    }

    /// Extract with `mw_tx`.
    pub fn extract_tx_with_mweb(&self) -> Result<Transaction, Error> {
        extract_tx_with_mweb(&self.psbt)
    }

    /// Populate maps from an assembled body.
    pub fn populate_maps_from_mw(&mut self, mw: &MwebTransaction, coins: &[MwebCoin]) {
        populate_psbt_from_mw(&mut self.psbt, mw, coins);
    }

    /// Alias used by fund path.
    pub fn populate_maps_from_mw_public(&mut self, mw: &MwebTransaction, coins: &[MwebCoin]) {
        self.populate_maps_from_mw(mw, coins);
    }

    /// Access parallel input maps.
    pub fn mweb_inputs(&self) -> &[MwebInput] {
        &self.psbt.mweb_inputs
    }

    /// Access parallel output maps.
    pub fn mweb_outputs(&self) -> &[MwebOutput] {
        &self.psbt.mweb_outputs
    }

    /// Access kernel maps.
    pub fn kernels(&self) -> &[MwebKernel] {
        &self.psbt.mweb_kernels
    }

    /// No-op: native PSBT encodes maps on serialize.
    pub fn apply_unknown_maps(&mut self) {}

    /// Completeness check.
    pub fn is_mweb_complete(&self) -> bool {
        is_mweb_complete(&self.psbt)
    }
}

// Silence unused-import warnings for items kept for call-site docs.
#[allow(dead_code)]
fn _native_reexport_anchor() {
    let _ = native::MWEB_TX_OFFSET_TYPE;
    let _ = mw::KernelFeatures::FeeFeatureBit;
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::keys::{MasterKeyScheme, MasterKeys};
    use crate::psbt_fund::{fund_mweb_spend, sign_funded_mweb};
    use crate::tx_builder::{build_pegin, MwebTxBuilder};
    use bitcoin::{Network, NetworkKind};

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
        let k = MwebKernel {
            excess_commit: Some([2u8; 33]),
            fee: Some(1000),
            features: Some(0),
            ..MwebKernel::default()
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
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
        .unwrap();
        let recv = keys.address(1, NetworkKind::Test, &secp).unwrap();

        let pegin = build_pegin(&keys, 1, 1_000_000, 50_000, NetworkKind::Test, &secp).unwrap();
        let coin = pegin.outputs[0].clone();
        let send_amt = coin.amount - 50_000;
        let finished = MwebTxBuilder::new()
            .add_input(coin.clone())
            .add_recipient(recv, send_amt)
            .fee(50_000)
            .finish(&keys, 0, NetworkKind::Test, &secp)
            .unwrap();

        let mut psbt = psbt_from_finished_mweb_tx(&finished).unwrap();
        assert!(!psbt.mweb_inputs.is_empty());
        assert!(!psbt.mweb_outputs.is_empty());
        assert!(!psbt.mweb_kernels.is_empty());
        assert_eq!(psbt.mweb_inputs[0].amount, Some(coin.amount));
        assert_eq!(psbt.mweb_inputs[0].shared_secret, Some(coin.shared_secret));
        assert!(psbt.mweb_inputs[0].signature.is_some());
        assert!(psbt.mweb_outputs[0].range_proof.is_some());
        assert!(psbt.mweb_kernels[0].signature.is_some());

        sign_mweb_components(&mut psbt, &finished.spent_coins, &secp).unwrap();
        let tx = extract_tx_with_mweb(&psbt).unwrap();
        assert!(tx.mw_tx.is_some());
        assert_eq!(
            tx.mw_tx.as_ref().unwrap().body.inputs[0].output_id,
            coin.output_id
        );
    }

    #[test]
    fn fund_sign_extract_emits_stealth_and_scrubs() {
        let secp = Secp256k1::new();
        let seed = [11u8; 32];
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
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
        assert!(funded.psbt.mweb_tx_offset.is_none());
        assert!(funded.psbt.mweb_inputs[0].master_scan_key_origin.is_none());
        assert!(funded.psbt.mweb_inputs[0].master_spend_key_origin.is_none());
        let desc = funded.psbt.mweb_inputs[0]
            .address_descriptor
            .clone()
            .expect("updater descriptor");
        assert!(desc.starts_with("mweb("), "{desc}");
        assert!(desc.contains(&format!("{}", keys.master_fingerprint)));
        validate_mweb_key_origins(&funded.psbt).unwrap();
        validate_mweb_key_origins_against(&funded.psbt, &keys).unwrap();
        // Tamper fingerprint in the descriptor → against-wallet validate must reject.
        {
            funded.psbt.mweb_inputs[0].address_descriptor =
                Some(desc.replace(&format!("{}", keys.master_fingerprint), "ffffffff"));
            assert!(validate_mweb_key_origins_against(&funded.psbt, &keys).is_err());
            populate_mweb_key_origins(&mut funded.psbt, &keys, &secp);
        }
        // Funded packet is PSBTv2; descriptor survives a serialize round-trip.
        {
            let decoded = Psbt::deserialize(&funded.psbt.serialize()).unwrap();
            assert_eq!(decoded.version, 2);
            assert_eq!(
                decoded.mweb_inputs[0].address_descriptor,
                funded.psbt.mweb_inputs[0].address_descriptor
            );
        }
        assert_eq!(
            funded.psbt.mweb_outputs[0]
                .stealth_address
                .as_ref()
                .unwrap()
                .len(),
            66
        );
        assert!(funded.psbt.mweb_inputs[0].signature.is_none());

        sign_funded_mweb(&mut funded, &keys, &secp).unwrap();
        assert!(funded.psbt.mweb_tx_offset.is_some(), "offsets set at sign");
        assert!(funded.psbt.mweb_inputs[0].signature.is_some());
        assert!(funded.psbt.mweb_inputs[0].amount.is_none());
        assert!(funded.psbt.mweb_inputs[0].shared_secret.is_none());
        assert!(funded.psbt.mweb_inputs[0].address_index.is_none());
        // Descriptor (scan WIF) is scrubbed; reserved origins stay absent.
        assert!(funded.psbt.mweb_inputs[0].address_descriptor.is_none());
        assert!(funded.psbt.mweb_inputs[0].master_scan_key_origin.is_none());
        assert!(funded
            .psbt
            .mweb_outputs
            .iter()
            .any(|o| o.stealth_address.is_some()));

        let tx = extract_tx_with_mweb(&funded.psbt).unwrap();
        assert!(tx.mw_tx.is_some());
        assert_eq!(
            tx.mw_tx.as_ref().unwrap().body.inputs[0].output_id,
            coin.output_id
        );
        let bytes = funded.psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(decoded.version, 2);
        assert!(decoded.mweb_inputs[0].address_descriptor.is_none());
        assert!(decoded.mweb_inputs[0].master_scan_key_origin.is_none());
        assert_eq!(decoded.mweb_kernels.len(), funded.psbt.mweb_kernels.len());
    }

    #[test]
    fn fund_sign_pegin_maps_first_kernel_id() {
        use crate::psbt_fund::{fund_mweb_pegin, sign_funded_mweb_pegin};
        let secp = Secp256k1::new();
        let seed = [13u8; 32];
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
        .unwrap();
        let mut funded =
            fund_mweb_pegin(&keys, 2, 1_000_000, 50_000, NetworkKind::Test, &secp).unwrap();
        assert!(funded.psbt.mweb_inputs.is_empty());
        assert_eq!(funded.psbt.mweb_outputs.len(), 1);
        let kid = sign_funded_mweb_pegin(&mut funded, &keys, &secp).unwrap();
        assert_eq!(funded.kernel_id, Some(kid));
        assert_eq!(funded.outputs.len(), 1);
        assert!(funded.psbt.mweb_tx_offset.is_some());
        let tx = extract_tx_with_mweb(&funded.psbt).unwrap();
        let mw = tx.mw_tx.as_ref().unwrap();
        assert_eq!(crate::tx_builder::kernel_id(&mw.body.kernels[0]), kid);
        let bytes = funded.psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(decoded.mweb_kernels.len(), 1);
        assert_eq!(decoded.mweb_outputs.len(), 1);
        assert_eq!(
            decoded.mweb_outputs[0]
                .stealth_address
                .as_ref()
                .unwrap()
                .len(),
            66
        );
    }
}
