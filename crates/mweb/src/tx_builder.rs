//! MWEB transaction builder (`TxBuilder::BuildTx` / Output·Input·Kernel::Create).
//!
//! Authors MWEB→MWEB spends, peg-ins, and peg-outs (Phase 5).

use alloc::vec::Vec;

use bitcoin::address::AddressData;
use bitcoin::blockdata::mimblewimble::{
    self as mweb, Input, Kernel, KernelFeatures, Output, OutputFeatures, OutputMessage,
    OutputMessageStandardFields, PegOutCoin, TxBody,
};
use bitcoin::consensus::encode::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Address, NetworkKind, ScriptBuf, Transaction, TxIn, TxOut};

use crate::coin_db::MwebCoin;
use crate::crypto::{
    blind_sum, blind_switch, bulletproof_prove, commitment_to_pubkey, pedersen_commit,
    random_secret, schnorr_sign, secret_add, secret_mul,
};
use crate::error::Error;
use crate::hash::{
    blake3_hash, hashed, hashed_pubkey, hashed_secret, nonce_mask, send_key_hash, value_mask,
    HashTag,
};
use crate::keys::MasterKeys;
use crate::scan::output_id;

/// Core change address index convention.
pub const CHANGE_ADDRESS_INDEX: u32 = 0;

/// Finished MWEB spend (or peg-out) ready for broadcast.
///
/// Prefer [`crate::fund_mweb_spend`] → [`crate::sign_funded_mweb`] → extract for the
/// ltcsuite in-PSBT happy path. This type remains for unit tests and migration helpers;
/// do not treat [`Self::tx`]'s pre-built `mw_tx` as the PSBT source of truth.
///
/// Wallet facade marks `build_mweb_*` deprecated in favor of fund→sign→extract.
#[derive(Debug, Clone)]
pub struct FinishedMwebTx {
    /// Litecoin transaction with empty vin/vout and `mw_tx` set.
    pub tx: Transaction,
    /// Change coin produced by this spend (if change amount > 0).
    pub change: Option<MwebCoin>,
    /// Output ids of spent inputs.
    pub spent_output_ids: Vec<[u8; 32]>,
    /// Spent input coins (secrets for PSBT map population / [`crate::MwebPsbt::sign_mweb_components`]).
    pub spent_coins: Vec<MwebCoin>,
}

/// Finished BDK-authored peg-in body (author `mw_tx` before the transparent v9 half).
#[derive(Debug, Clone)]
pub struct FinishedMwebPegin {
    /// MWEB transaction body to attach after PSBT extract.
    pub mw_tx: mweb::Transaction,
    /// Peg-in kernel id (= Core `Kernel::GetHash` = v9 witness program).
    pub kernel_id: [u8; 32],
    /// Transparent v9 output value (= kernel `pegin` amount).
    pub pegin_amount: u64,
    /// Owned stealth outputs for insertion after confirmation.
    pub outputs: Vec<MwebCoin>,
}

/// Builder for MWEB spends and peg-outs.
///
/// Prefer [`crate::fund_mweb_spend`] / [`crate::sign_funded_mweb`] for production sends.
/// Kept for unit/regtest vectors; wallet `build_mweb_*` APIs are deprecated.
#[derive(Debug, Default, Clone)]
pub struct MwebTxBuilder {
    inputs: Vec<MwebCoin>,
    recipients: Vec<(Address, u64)>,
    pegouts: Vec<(ScriptBuf, u64)>,
    fee: u64,
}

impl MwebTxBuilder {
    /// Empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an owned unspent MWEB coin as an input.
    pub fn add_input(mut self, coin: MwebCoin) -> Self {
        self.inputs.push(coin);
        self
    }

    /// Add a recipient stealth address and amount (litoshis).
    pub fn add_recipient(mut self, address: Address, amount: u64) -> Self {
        self.recipients.push((address, amount));
        self
    }

    /// Add a peg-out to a transparent `script_pubkey`.
    pub fn add_pegout(mut self, script_pubkey: ScriptBuf, amount: u64) -> Self {
        self.pegouts.push((script_pubkey, amount));
        self
    }

    /// Explicit fee in litoshis (kernel fee feature).
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Build a balanced MWEB transaction (MWEB→MWEB and/or peg-out).
    ///
    /// Change (if any) goes to `keys.address(change_index, network)`.
    pub fn finish(
        self,
        keys: &MasterKeys,
        change_index: u32,
        network: NetworkKind,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, Error> {
        let input_total: u64 = self.inputs.iter().map(|c| c.amount).sum();
        let recipient_total: u64 = self.recipients.iter().map(|(_, a)| *a).sum();
        let pegout_total: u64 = self.pegouts.iter().map(|(_, a)| *a).sum();
        let needed = recipient_total
            .saturating_add(pegout_total)
            .saturating_add(self.fee);
        if input_total < needed {
            return Err(Error::InsufficientFunds);
        }
        let change_amount = input_total - needed;

        let mut all_recipients = self.recipients;
        let change_pos = if change_amount > 0 {
            let change_addr = keys.address(change_index, network, secp)?;
            all_recipients.push((change_addr, change_amount));
            Some(all_recipients.len() - 1)
        } else {
            None
        };

        let assembled = assemble_body(
            &self.inputs,
            &all_recipients,
            change_pos.map(|i| (i, change_index)),
            keys,
            self.fee,
            None, // no peg-in
            &self.pegouts,
            secp,
        )?;

        let tx = wrap_mweb_only(assembled.mw_tx.clone());
        Ok(FinishedMwebTx {
            tx,
            change: assembled.change,
            spent_output_ids: assembled.spent_output_ids,
            spent_coins: self.inputs,
        })
    }
}

/// Author a peg-in `mw_tx` (no MWEB inputs) sending `pegin_amount - fee` to `receive_index`.
///
/// Prefer [`crate::fund_mweb_pegin`] / [`crate::sign_funded_mweb_pegin`] (maps-first).
#[deprecated(
    since = "0.1.0",
    note = "use fund_mweb_pegin + sign_funded_mweb_pegin (maps-first) instead"
)]
pub fn build_pegin(
    keys: &MasterKeys,
    receive_index: u32,
    pegin_amount: u64,
    fee: u64,
    network: NetworkKind,
    secp: &Secp256k1<All>,
) -> Result<FinishedMwebPegin, Error> {
    if pegin_amount <= fee {
        return Err(Error::InsufficientFunds);
    }
    let receive_amount = pegin_amount - fee;
    let addr = keys.address(receive_index, network, secp)?;
    let recipients = vec![(addr, receive_amount)];

    let assembled = assemble_body(
        &[],
        &recipients,
        Some((0, receive_index)), // sole output is owned at receive_index
        keys,
        fee,
        Some(pegin_amount as i64),
        &[],
        secp,
    )?;

    let kernel = assembled
        .mw_tx
        .body
        .kernels
        .first()
        .ok_or(Error::Crypto("peg-in missing kernel".into()))?;
    let kernel_id = kernel_id(kernel);

    let mut outputs = Vec::new();
    if let Some(c) = assembled.change {
        outputs.push(c);
    }

    Ok(FinishedMwebPegin {
        mw_tx: assembled.mw_tx,
        kernel_id,
        pegin_amount,
        outputs,
    })
}

/// Core `Kernel::GetHash` / `GetKernelID`: untagged BLAKE3 of consensus-serialized kernel.
pub fn kernel_id(kernel: &Kernel) -> [u8; 32] {
    blake3_hash(&serialize(kernel))
}

struct AssembledBody {
    mw_tx: mweb::Transaction,
    change: Option<MwebCoin>,
    spent_output_ids: Vec<[u8; 32]>,
}

#[allow(clippy::too_many_arguments)]
fn assemble_body(
    input_coins: &[MwebCoin],
    recipients: &[(Address, u64)],
    owned_output: Option<(usize, u32)>,
    keys: &MasterKeys,
    fee: u64,
    pegin: Option<i64>,
    pegouts: &[(ScriptBuf, u64)],
    secp: &Secp256k1<All>,
) -> Result<AssembledBody, Error> {
    let mut outputs = Vec::with_capacity(recipients.len());
    let mut out_blinds = Vec::with_capacity(recipients.len());
    let mut out_keys = Vec::with_capacity(recipients.len());
    let mut change_coin = None;

    for (i, (addr, amount)) in recipients.iter().enumerate() {
        let (raw_blind, sender_key, output) = create_output(addr, *amount, secp)?;
        let switched = blind_switch(&raw_blind, *amount, secp)?;
        out_blinds.push(switched);
        out_keys.push(sender_key);

        if let Some((pos, index)) = owned_output {
            if pos == i {
                let (t, spend) = shared_secret_and_spend_for_owned(
                    keys,
                    index,
                    &output
                        .message
                        .standard_fields
                        .as_ref()
                        .ok_or(Error::Crypto("missing standard fields".into()))?
                        .key_exchange_pubkey,
                    &output.receiver_public_key,
                    secp,
                )?;
                change_coin = Some(MwebCoin {
                    output_id: output_id(&output),
                    commitment: output.commitment,
                    amount: *amount,
                    address_index: index,
                    blind: raw_blind,
                    shared_secret: t,
                    spend_key: Some(spend),
                    block_height: None,
                    is_pegin: pegin.is_some(),
                    leaf_index: None,
                });
            }
        }
        outputs.push(output);
    }

    let mut inputs = Vec::with_capacity(input_coins.len());
    let mut in_blinds = Vec::with_capacity(input_coins.len());
    let mut in_keys_pos = Vec::with_capacity(input_coins.len());
    let mut in_keys_neg = Vec::with_capacity(input_coins.len());
    let mut spent_output_ids = Vec::with_capacity(input_coins.len());

    for coin in input_coins {
        let spend_key = coin.spend_key.ok_or(Error::MissingCoinSecrets)?;
        let switched = blind_switch(&coin.blind, coin.amount, secp)?;
        let ephemeral = random_secret(secp);
        let input = create_input(
            &coin.output_id,
            &coin.commitment,
            &ephemeral,
            &spend_key,
            secp,
        )?;
        in_blinds.push(switched);
        in_keys_pos.push(ephemeral);
        in_keys_neg.push(spend_key);
        spent_output_ids.push(coin.output_id);
        inputs.push(input);
    }

    // kernel_blind = outs - ins - kernel_offset (missing sides omitted).
    let kernel_offset = random_secret(secp);
    let pos = out_blinds;
    let mut neg = in_blinds;
    neg.push(kernel_offset);
    let kernel_blind = if pos.is_empty() {
        // outs = 0 → kernel_blind = -(ins + offset)
        let sum_neg = blind_sum(&neg, &[])?;
        blind_sum(&[], &[sum_neg])?
    } else {
        blind_sum(&pos, &neg)?
    };

    let stealth_blind = random_secret(secp);
    let pegout_coins: Vec<PegOutCoin> = pegouts
        .iter()
        .map(|(spk, amt)| PegOutCoin {
            amount: *amt as i64,
            script_pub_key: spk.clone(),
        })
        .collect();

    let kernel = create_kernel(
        kernel_blind,
        Some(stealth_blind),
        Some(fee as i64),
        pegin,
        &pegout_coins,
        secp,
    )?;

    let mut stealth_pos = out_keys;
    stealth_pos.extend(in_keys_pos);
    let mut stealth_neg = in_keys_neg;
    stealth_neg.push(stealth_blind);
    let stealth_offset = if stealth_pos.is_empty() {
        // No output/ephemeral keys: stealth_offset = -stealth_blind
        blind_sum(&[], &stealth_neg)?
    } else {
        blind_sum(&stealth_pos, &stealth_neg)?
    };

    inputs.sort_by(|a, b| a.output_id.cmp(&b.output_id));
    outputs.sort_by(|a, b| output_id(a).cmp(&output_id(b)));

    Ok(AssembledBody {
        mw_tx: mweb::Transaction {
            kernel_offset,
            stealth_offset,
            body: TxBody {
                inputs,
                outputs,
                kernels: vec![kernel],
            },
        },
        change: change_coin,
        spent_output_ids,
    })
}

fn wrap_mweb_only(mw_tx: mweb::Transaction) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::<TxIn>::new(),
        output: Vec::<TxOut>::new(),
        mw_tx: Some(mw_tx),
        is_hog_ex: false,
    }
}

fn mweb_stealth_keys(addr: &Address) -> Result<(PublicKey, PublicKey), Error> {
    match addr.to_address_data() {
        AddressData::Mweb { scan, spend } => {
            let a = PublicKey::from_slice(&scan)?;
            let b = PublicKey::from_slice(&spend)?;
            Ok((a, b))
        }
        _ => Err(Error::NotMwebAddress),
    }
}

/// Core `Output::Create` with a fresh random sender key.
pub fn create_output(
    recipient: &Address,
    value: u64,
    secp: &Secp256k1<All>,
) -> Result<([u8; 32], [u8; 32], Output), Error> {
    let sender_privkey = random_secret(secp);
    create_output_with_sender(recipient, value, &sender_privkey, secp)
}

/// Core `Output::Create` with an explicit sender secret (deterministic fixtures / ltcd parity).
pub fn create_output_with_sender(
    recipient: &Address,
    value: u64,
    sender_privkey: &[u8; 32],
    secp: &Secp256k1<All>,
) -> Result<([u8; 32], [u8; 32], Output), Error> {
    let (a, b) = mweb_stealth_keys(recipient)?;
    let sender_sk = SecretKey::from_slice(sender_privkey.as_ref())?;

    let n_full = hashed_secret(HashTag::Nonce, &sender_sk);
    let mut n = [0u8; 16];
    n.copy_from_slice(&n_full[..16]);

    let s = send_key_hash(&a, &b, value, &n);
    let s_scalar = Scalar::from_be_bytes(s).map_err(|_| Error::InvalidTweak)?;
    let s_a = a.mul_tweak(secp, &s_scalar)?;
    let t = hashed_pubkey(HashTag::Derive, &s_a);
    let out_key = hashed(HashTag::OutKey, &t);
    let out_key_scalar = Scalar::from_be_bytes(out_key).map_err(|_| Error::InvalidTweak)?;
    let ko = b.mul_tweak(secp, &out_key_scalar)?;
    let ke = b.mul_tweak(secp, &s_scalar)?;

    let raw_blind = hashed(HashTag::Blind, &t);
    let switched = blind_switch(&raw_blind, value, secp)?;
    let commitment = pedersen_commit(value, &switched, secp)?;

    let ks = PublicKey::from_secret_key(secp, &sender_sk);
    let view_tag = hashed_pubkey(HashTag::Tag, &s_a)[0];
    let mv = value ^ value_mask(&t);
    let mut mn = [0u8; 16];
    let nm = nonce_mask(&t);
    for i in 0..16 {
        mn[i] = n[i] ^ nm[i];
    }

    let features = OutputFeatures::StandardFieldsFeatureBit as u8;
    let message = OutputMessage {
        features,
        standard_fields: Some(OutputMessageStandardFields {
            key_exchange_pubkey: ke,
            view_tag,
            masked_value: mv,
            masked_nonce: mn,
        }),
        extra_data: Vec::new(),
    };
    let msg_ser = serialize(&message);
    let range_proof = bulletproof_prove(value, &switched, &msg_ser)?;

    let msg_hash = blake3_hash(&msg_ser);
    let proof_hash = blake3_hash(&range_proof);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&commitment);
    hasher.update(&ks.serialize());
    hasher.update(&ko.serialize());
    hasher.update(&msg_hash);
    hasher.update(&proof_hash);
    let sig_message = *hasher.finalize().as_bytes();
    let signature = schnorr_sign(sender_privkey, &sig_message)?;

    Ok((
        raw_blind,
        *sender_privkey,
        Output {
            commitment,
            sender_public_key: ks,
            receiver_public_key: ko,
            message,
            range_proof,
            signature,
        },
    ))
}

/// Core `Input::Create` (stealth feature bit).
pub fn create_input(
    output_id: &[u8; 32],
    commitment: &[u8; 33],
    input_key: &[u8; 32],
    output_key: &[u8; 32],
    secp: &Secp256k1<All>,
) -> Result<Input, Error> {
    let features = 0x01u8; // STEALTH_KEY_FEATURE_BIT
    let input_sk = SecretKey::from_slice(input_key)?;
    let output_sk = SecretKey::from_slice(output_key)?;
    let input_pk = PublicKey::from_secret_key(secp, &input_sk);
    let output_pk = PublicKey::from_secret_key(secp, &output_sk);

    let mut key_hasher = blake3::Hasher::new();
    key_hasher.update(&input_pk.serialize());
    key_hasher.update(&output_pk.serialize());
    let key_hash = *key_hasher.finalize().as_bytes();

    let ko_term = secret_mul(output_key, &key_hash)?;
    let sig_key = secret_add(input_key, &ko_term)?;

    let mut msg_hasher = blake3::Hasher::new();
    msg_hasher.update(&[features]);
    msg_hasher.update(output_id);
    let msg_hash = *msg_hasher.finalize().as_bytes();
    let signature = schnorr_sign(&sig_key, &msg_hash)?;

    Ok(Input {
        features,
        output_id: *output_id,
        commitment: *commitment,
        input_public_key: Some(input_pk),
        output_public_key: output_pk,
        extra_data: Vec::new(),
        signature,
    })
}

/// Encode Core `WriteVarInt` / MWEB amount for kernel signature messages.
fn write_mweb_varint(amount: i64) -> Vec<u8> {
    let mut n = amount;
    const SIZE: usize = 10;
    let mut tmp = [0u8; SIZE];
    let mut len = 0;
    loop {
        let a = (n & 0x7f) as u8;
        let b = if len != 0 { 0x80 } else { 0x00 };
        tmp[len] = a | b;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    len += 1;
    let mut out = Vec::with_capacity(len);
    for i in (0..len).rev() {
        out.push(tmp[i]);
    }
    out
}

/// Core `Kernel::Create`.
pub fn create_kernel(
    blind: [u8; 32],
    stealth_blind: Option<[u8; 32]>,
    fee: Option<i64>,
    pegin: Option<i64>,
    pegouts: &[PegOutCoin],
    secp: &Secp256k1<All>,
) -> Result<Kernel, Error> {
    let mut features = 0u8;
    if fee.is_some() {
        features |= KernelFeatures::FeeFeatureBit as u8;
    }
    if pegin.is_some() {
        features |= KernelFeatures::PeginFeatureBit as u8;
    }
    if !pegouts.is_empty() {
        features |= KernelFeatures::PegoutFeatureBit as u8;
    }
    if stealth_blind.is_some() {
        features |= KernelFeatures::StealthExcessFeatureBit as u8;
    }

    let excess = pedersen_commit(0, &blind, secp)?;
    let mut sig_key = blind;
    let stealth_excess = if let Some(sb) = stealth_blind {
        let sb_sk = SecretKey::from_slice(&sb)?;
        let stealth_pk = PublicKey::from_secret_key(secp, &sb_sk);
        let excess_pk = commitment_to_pubkey(&excess)?;
        let mut h = blake3::Hasher::new();
        h.update(&excess_pk.serialize());
        h.update(&stealth_pk.serialize());
        let h_hash = *h.finalize().as_bytes();
        let mul = secret_mul(&blind, &h_hash)?;
        sig_key = secret_add(&mul, &sb)?;
        Some(stealth_pk)
    } else {
        None
    };

    // Core `Kernel::GetSignatureMessage` field order.
    let mut msg = Vec::new();
    msg.push(features);
    msg.extend_from_slice(&excess);
    if let Some(f) = fee {
        msg.extend_from_slice(&write_mweb_varint(f));
    }
    if let Some(p) = pegin {
        msg.extend_from_slice(&write_mweb_varint(p));
    }
    if !pegouts.is_empty() {
        // CompactSize count then each PegOutCoin (matches litecoin Kernel encode).
        msg.extend_from_slice(&serialize(&pegouts.to_vec()));
    }
    if let Some(pk) = stealth_excess.as_ref() {
        msg.extend_from_slice(&pk.serialize());
    }
    let sig_message = blake3_hash(&msg);
    let signature = schnorr_sign(&sig_key, &sig_message)?;

    Ok(Kernel {
        features,
        fee,
        pegin,
        pegouts: pegouts.to_vec(),
        lock_height: None,
        stealth_excess,
        extra_data: Vec::new(),
        excess,
        signature,
    })
}

/// Derive shared secret + spend key for an owned output (change / self-send).
pub fn shared_secret_and_spend_for_owned(
    keys: &MasterKeys,
    index: u32,
    ke: &PublicKey,
    ko: &PublicKey,
    secp: &Secp256k1<All>,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let scan_scalar =
        Scalar::from_be_bytes(keys.scan.secret_bytes()).map_err(|_| Error::InvalidTweak)?;
    let shared_point = ke.mul_tweak(secp, &scan_scalar)?;
    let t = hashed_pubkey(HashTag::Derive, &shared_point);
    let out_key = hashed(HashTag::OutKey, &t);
    let out_key_scalar = Scalar::from_be_bytes(out_key).map_err(|_| Error::InvalidTweak)?;
    let b_i = keys.spend_key_at(index)?;
    let expected_ko = PublicKey::from_secret_key(secp, &b_i).mul_tweak(secp, &out_key_scalar)?;
    if expected_ko != *ko {
        return Err(Error::Crypto("owned output Ko mismatch".into()));
    }
    let spend = b_i.mul_tweak(&out_key_scalar)?.secret_bytes();
    Ok((t, spend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hex::FromHex;

    #[test]
    fn fixture_kernel_id_matches_v9_program() {
        // docs/mweb_pegin_regtest.hex — kernel_id from MWEB_PEGIN.md
        let hex = include_str!("../../../docs/mweb_pegin_regtest.hex");
        let raw = Vec::from_hex(hex.trim()).expect("fixture hex");
        let tx: Transaction = deserialize(&raw).expect("fixture tx");
        let mw = tx.mw_tx.as_ref().expect("mw_tx");
        let kernel = mw.body.kernels.first().expect("kernel");
        let id = kernel_id(kernel);
        let expected = <[u8; 32]>::try_from(
            Vec::from_hex("a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        assert_eq!(id, expected, "Kernel::GetHash must equal v9 program / vkern.kernel_id");

        let v9 = tx
            .output
            .iter()
            .find(|o| o.script_pubkey.as_bytes().first() == Some(&0x59))
            .expect("v9 out");
        assert_eq!(&v9.script_pubkey.as_bytes()[2..34], &id);
    }
}
