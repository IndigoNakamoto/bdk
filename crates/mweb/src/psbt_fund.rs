//! In-PSBT fund → sign → scrub lifecycle (ltcwallet `SignMwebComponents` shape).
//!
//! Funding stages typed MWEB maps **without** an assembled [`MwebTransaction`]. Signing fills
//! input/kernel signatures and offsets, then extract builds `mw_tx` from maps only.

use alloc::vec::Vec;

use bitcoin::address::AddressData;
use bitcoin::blockdata::mimblewimble::{
    self as mweb, KernelFeatures, PegOutCoin, TxBody, Transaction as MwebTransaction,
};
use bitcoin::consensus::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::All;
use bitcoin::transaction::Version;
use bitcoin::{Address, NetworkKind, ScriptBuf, Transaction};

use crate::coin_db::MwebCoin;
use crate::crypto::{blind_sum, blind_switch, random_secret};
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::psbt::{
    MwebPsbt, MwebPsbtInput, MwebPsbtKernel, MwebPsbtOutput,
};
use crate::scan::output_id;
use crate::tx_builder::{
    create_input, create_kernel, create_output, CHANGE_ADDRESS_INDEX,
};

/// Staged output produced during fund (blinds kept off-PSBT until sign).
#[derive(Debug, Clone)]
pub struct StagedMwebOutput {
    /// Wire output (rangeproof + output sig already present).
    pub output: mweb::Output,
    /// Pre-switch blinding factor.
    pub raw_blind: [u8; 32],
    /// Sender ephemeral key used to create the output.
    pub sender_key: [u8; 32],
    /// Recipient amount.
    pub amount: u64,
    /// When this output is wallet change, the address index.
    pub change_index: Option<u32>,
}

/// Funded but unsigned MWEB spend (no `mw_tx` yet).
#[derive(Debug, Clone)]
pub struct FundedMwebPsbt {
    /// PSBT with MWEB maps; [`MwebPsbt::mw_tx`] is `None` until sign.
    pub mweb: MwebPsbt,
    /// Input coins (secrets for signing).
    pub spent_coins: Vec<MwebCoin>,
    /// Staged outputs (pre-sort order matching fund creation).
    pub staged_outputs: Vec<StagedMwebOutput>,
    /// Kernel fee (litoshis).
    pub fee: u64,
    /// Peg-out destinations.
    pub pegouts: Vec<(ScriptBuf, u64)>,
}

/// Fund an MWEB→MWEB / peg-out spend: populate maps, leave `mw_tx` unset.
pub fn fund_mweb_spend(
    inputs: Vec<MwebCoin>,
    recipients: Vec<(Address, u64)>,
    pegouts: Vec<(ScriptBuf, u64)>,
    fee: u64,
    keys: &MasterKeys,
    change_index: u32,
    network: NetworkKind,
    secp: &Secp256k1<All>,
) -> Result<FundedMwebPsbt, Error> {
    if inputs.is_empty() {
        return Err(Error::MissingCoinSecrets);
    }
    let input_total: u64 = inputs.iter().map(|c| c.amount).sum();
    let recipient_total: u64 = recipients.iter().map(|(_, a)| *a).sum();
    let pegout_total: u64 = pegouts.iter().map(|(_, a)| *a).sum();
    let needed = recipient_total
        .saturating_add(pegout_total)
        .saturating_add(fee);
    if input_total < needed {
        return Err(Error::InsufficientFunds);
    }
    let change_amount = input_total - needed;

    let mut all_recipients = recipients;
    let mut change_pos = None;
    if change_amount > 0 {
        let change_addr = keys.address(change_index, network, secp)?;
        change_pos = Some(all_recipients.len());
        all_recipients.push((change_addr, change_amount));
    }

    let mut staged = Vec::with_capacity(all_recipients.len());
    let mut mweb_outputs = Vec::with_capacity(all_recipients.len());
    for (i, (addr, amount)) in all_recipients.iter().enumerate() {
        let (raw_blind, sender_key, output) = create_output(addr, *amount, secp)?;
        let mut mapped = MwebPsbtOutput::from_mweb_output(&output);
        mapped.stealth_address = Some(stealth_address_bytes(addr)?);
        mweb_outputs.push(mapped);
        staged.push(StagedMwebOutput {
            output,
            raw_blind,
            sender_key,
            amount: *amount,
            change_index: if Some(i) == change_pos {
                Some(change_index)
            } else {
                None
            },
        });
    }

    let mut mweb_inputs = Vec::with_capacity(inputs.len());
    for coin in &inputs {
        let mut inp = MwebPsbtInput {
            output_id: Some(coin.output_id),
            commit: Some(coin.commitment),
            amount: Some(coin.amount),
            address_index: Some(coin.address_index),
            shared_secret: Some(coin.shared_secret),
            features: Some(0x01), // stealth feature expected at sign
            ..MwebPsbtInput::default()
        };
        inp.enrich_from_coin(coin);
        mweb_inputs.push(inp);
    }

    let mut features = 0u8;
    if fee > 0 {
        features |= KernelFeatures::FeeFeatureBit as u8;
    }
    if !pegouts.is_empty() {
        features |= KernelFeatures::PegoutFeatureBit as u8;
    }
    features |= KernelFeatures::StealthExcessFeatureBit as u8;

    let pegout_ser = if pegouts.is_empty() {
        None
    } else {
        let coins: Vec<PegOutCoin> = pegouts
            .iter()
            .map(|(spk, amt)| PegOutCoin {
                amount: *amt as i64,
                script_pub_key: spk.clone(),
            })
            .collect();
        Some(serialize(&coins))
    };

    let kernel = MwebPsbtKernel {
        fee: (fee > 0).then_some(fee),
        pegout: pegout_ser,
        features: Some(features),
        ..MwebPsbtKernel::default()
    };

    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
        mw_tx: None,
        is_hog_ex: false,
    };
    let psbt = Psbt::from_unsigned_tx(unsigned)
        .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;

    let mut mweb = MwebPsbt::from_psbt(psbt);
    mweb.mweb_inputs = mweb_inputs;
    mweb.mweb_outputs = mweb_outputs;
    mweb.kernels = vec![kernel];
    mweb.mw_tx = None;
    mweb.apply_unknown_maps();

    let _ = CHANGE_ADDRESS_INDEX; // documented convention; change_index is explicit
    Ok(FundedMwebPsbt {
        mweb,
        spent_coins: inputs,
        staged_outputs: staged,
        fee,
        pegouts,
    })
}

/// Sign a funded MWEB PSBT: create inputs/kernel, set offsets into maps, scrub secrets.
///
/// Leaves [`MwebPsbt::mw_tx`] unset — assemble only at [`MwebPsbt::extract_tx_with_mweb`].
pub fn sign_funded_mweb(
    funded: &mut FundedMwebPsbt,
    keys: &MasterKeys,
    secp: &Secp256k1<All>,
) -> Result<(), Error> {
    let mut outputs = Vec::with_capacity(funded.staged_outputs.len());
    let mut out_blinds = Vec::with_capacity(funded.staged_outputs.len());
    let mut out_keys = Vec::with_capacity(funded.staged_outputs.len());
    let mut change_coin = None;

    for staged in &funded.staged_outputs {
        let switched = blind_switch(&staged.raw_blind, staged.amount, secp)?;
        out_blinds.push(switched);
        out_keys.push(staged.sender_key);
        if let Some(index) = staged.change_index {
            let ke = staged
                .output
                .message
                .standard_fields
                .as_ref()
                .ok_or(Error::Crypto("missing standard fields".into()))?
                .key_exchange_pubkey;
            let (t, spend) = crate::tx_builder::shared_secret_and_spend_for_owned(
                keys,
                index,
                &ke,
                &staged.output.receiver_public_key,
                secp,
            )?;
            change_coin = Some(MwebCoin {
                output_id: output_id(&staged.output),
                commitment: staged.output.commitment,
                amount: staged.amount,
                address_index: index,
                blind: staged.raw_blind,
                shared_secret: t,
                spend_key: Some(spend),
                block_height: None,
                is_pegin: false,
                leaf_index: None,
            });
        }
        outputs.push(staged.output.clone());
    }

    let mut inputs = Vec::with_capacity(funded.spent_coins.len());
    let mut in_blinds = Vec::with_capacity(funded.spent_coins.len());
    let mut in_keys_pos = Vec::with_capacity(funded.spent_coins.len());
    let mut in_keys_neg = Vec::with_capacity(funded.spent_coins.len());

    for coin in &funded.spent_coins {
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
        inputs.push(input);
    }

    let kernel_offset = random_secret(secp);
    let pos = out_blinds;
    let mut neg = in_blinds;
    neg.push(kernel_offset);
    let kernel_blind = if pos.is_empty() {
        let sum_neg = blind_sum(&neg, &[])?;
        blind_sum(&[], &[sum_neg])?
    } else {
        blind_sum(&pos, &neg)?
    };

    let stealth_blind = random_secret(secp);
    let pegout_coins: Vec<PegOutCoin> = funded
        .pegouts
        .iter()
        .map(|(spk, amt)| PegOutCoin {
            amount: *amt as i64,
            script_pub_key: spk.clone(),
        })
        .collect();

    let kernel = create_kernel(
        kernel_blind,
        Some(stealth_blind),
        Some(funded.fee as i64),
        None,
        &pegout_coins,
        secp,
    )?;

    let mut stealth_pos = out_keys;
    stealth_pos.extend(in_keys_pos);
    let mut stealth_neg = in_keys_neg;
    stealth_neg.push(stealth_blind);
    let stealth_offset = if stealth_pos.is_empty() {
        blind_sum(&[], &stealth_neg)?
    } else {
        blind_sum(&stealth_pos, &stealth_neg)?
    };

    inputs.sort_by(|a, b| a.output_id.cmp(&b.output_id));
    outputs.sort_by(|a, b| output_id(a).cmp(&output_id(b)));

    let mw = MwebTransaction {
        kernel_offset,
        stealth_offset,
        body: TxBody {
            inputs,
            outputs,
            kernels: vec![kernel],
        },
    };

    // Preserve stealth addresses across remap.
    let stealth_by_commit: alloc::collections::BTreeMap<[u8; 33], Vec<u8>> = funded
        .mweb
        .mweb_outputs
        .iter()
        .filter_map(|o| {
            Some((*o.commit.as_ref()?, o.stealth_address.clone()?))
        })
        .collect();

    funded.mweb.populate_maps_from_mw_public(&mw, &funded.spent_coins);
    for out in &mut funded.mweb.mweb_outputs {
        if let Some(c) = out.commit {
            if let Some(sa) = stealth_by_commit.get(&c) {
                out.stealth_address = Some(sa.clone());
            }
        }
    }
    // Maps are the PSBT source of truth until extract.
    funded.mweb.mw_tx = None;
    let _ = mw;
    funded.mweb.apply_unknown_maps();
    funded.mweb.scrub_sensitive_fields();

    // Stash change on funded for wallet insert (optional).
    let _ = change_coin;
    Ok(())
}

/// Extract change coin from staged outputs after a successful sign (if any).
pub fn change_from_funded(funded: &FundedMwebPsbt, keys: &MasterKeys, secp: &Secp256k1<All>) -> Result<Option<MwebCoin>, Error> {
    for staged in &funded.staged_outputs {
        if let Some(index) = staged.change_index {
            let ke = staged
                .output
                .message
                .standard_fields
                .as_ref()
                .ok_or(Error::Crypto("missing standard fields".into()))?
                .key_exchange_pubkey;
            let (t, spend) = crate::tx_builder::shared_secret_and_spend_for_owned(
                keys,
                index,
                &ke,
                &staged.output.receiver_public_key,
                secp,
            )?;
            return Ok(Some(MwebCoin {
                output_id: output_id(&staged.output),
                commitment: staged.output.commitment,
                amount: staged.amount,
                address_index: index,
                blind: staged.raw_blind,
                shared_secret: t,
                spend_key: Some(spend),
                block_height: None,
                is_pegin: false,
                leaf_index: None,
            }));
        }
    }
    Ok(None)
}

fn stealth_address_bytes(addr: &Address) -> Result<Vec<u8>, Error> {
    match addr.to_address_data() {
        AddressData::Mweb { scan, spend } => {
            let mut v = Vec::with_capacity(66);
            v.extend_from_slice(&scan);
            v.extend_from_slice(&spend);
            Ok(v)
        }
        _ => Err(Error::NotMwebAddress),
    }
}
