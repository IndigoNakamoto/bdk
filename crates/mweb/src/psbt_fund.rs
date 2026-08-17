//! In-PSBT fund → sign → scrub lifecycle (ltcwallet `SignMwebComponents` shape).
//!
//! Funding stages typed MWEB maps on a native [`Psbt`] **without** an assembled
//! [`MwebTransaction`]. Signing fills input/kernel signatures and offsets, scrubs secrets,
//! then [`Psbt::extract_tx_with_mweb`] builds `mw_tx` from maps only.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::address::AddressData;
use bitcoin::address::MwebHrp;
use bitcoin::blockdata::mimblewimble::{
    self as mweb, KernelFeatures, PegOutCoin, Transaction as MwebTransaction, TxBody,
};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::mweb::{MwebInput, MwebKernel};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::All;
use bitcoin::transaction::Version;
use bitcoin::{Address, ScriptBuf, Transaction};

use crate::coin_db::MwebCoin;
use crate::crypto::{blind_sum, blind_switch, random_secret};
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::psbt::{
    enrich_input_from_coin, extract_tx_with_mweb, mweb_input_from_wire, mweb_kernel_from_wire,
    mweb_output_from_wire, scrub_sensitive_fields,
};
use crate::scan::output_id;
use crate::tx_builder::{
    checked_amount_total, create_input, create_kernel, create_output, money_to_i64,
    CHANGE_ADDRESS_INDEX,
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
    /// Native PSBT with MWEB maps; `mw_tx` is assembled only at extract.
    pub psbt: Psbt,
    /// Input coins (secrets for signing).
    pub spent_coins: Vec<MwebCoin>,
    /// Staged outputs (pre-sort order matching fund creation).
    pub staged_outputs: Vec<StagedMwebOutput>,
    /// Kernel fee (litoshis).
    pub fee: u64,
    /// Peg-out destinations.
    pub pegouts: Vec<(ScriptBuf, u64)>,
}

impl FundedMwebPsbt {
    /// Extract network tx after [`sign_funded_mweb`].
    pub fn extract_tx(&self) -> Result<Transaction, Error> {
        extract_tx_with_mweb(&self.psbt)
    }
}

/// Fund an MWEB→MWEB / peg-out spend: populate native maps, leave offsets/sigs unset.
pub fn fund_mweb_spend(
    inputs: Vec<MwebCoin>,
    recipients: Vec<(Address, u64)>,
    pegouts: Vec<(ScriptBuf, u64)>,
    fee: u64,
    keys: &MasterKeys,
    change_index: u32,
    network: impl Into<MwebHrp>,
    secp: &Secp256k1<All>,
) -> Result<FundedMwebPsbt, Error> {
    let network = network.into();
    if inputs.is_empty() {
        return Err(Error::MissingCoinSecrets);
    }
    let input_total = checked_amount_total(inputs.iter().map(|c| c.amount))?;
    let recipient_total = checked_amount_total(recipients.iter().map(|(_, a)| *a))?;
    let pegout_total = checked_amount_total(pegouts.iter().map(|(_, a)| *a))?;
    let needed = checked_amount_total([recipient_total, pegout_total, fee])?;
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
        let mut mapped = mweb_output_from_wire(&output);
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
        let mut inp = MwebInput {
            output_id: Some(coin.output_id),
            commit: Some(coin.commitment),
            amount: Some(coin.amount),
            address_index: Some(coin.address_index),
            shared_secret: Some(coin.shared_secret),
            features: Some(0x01), // stealth feature expected at sign
            ..MwebInput::default()
        };
        enrich_input_from_coin(&mut inp, coin);
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

    let pegouts_ser: Vec<Vec<u8>> = pegouts
        .iter()
        .map(|(spk, amt)| {
            Ok(bitcoin::psbt::mweb::pegout_psbt_value(&PegOutCoin {
                amount: money_to_i64(*amt, "peg-out amount")?,
                script_pub_key: spk.clone(),
            }))
        })
        .collect::<Result<_, Error>>()?;

    let kernel = MwebKernel {
        fee: (fee > 0).then_some(fee),
        pegouts: pegouts_ser,
        features: Some(features),
        ..MwebKernel::default()
    };

    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
        mw_tx: None,
        is_hog_ex: false,
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned)
        .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;

    psbt.mweb_inputs = mweb_inputs;
    psbt.mweb_outputs = mweb_outputs;
    psbt.mweb_kernels = vec![kernel];
    psbt.mweb_tx_offset = None;
    psbt.mweb_stealth_offset = None;

    crate::psbt::populate_mweb_key_origins(&mut psbt, keys, secp);
    crate::psbt::validate_mweb_key_origins_against(&psbt, keys)?;

    let _ = CHANGE_ADDRESS_INDEX;
    Ok(FundedMwebPsbt {
        psbt,
        spent_coins: inputs,
        staged_outputs: staged,
        fee,
        pegouts,
    })
}

/// Sign a funded MWEB PSBT: create inputs/kernel, set offsets into maps, scrub secrets.
///
/// Leaves `mw_tx` unset on the transparent skeleton — assemble only at
/// [`Psbt::extract_tx_with_mweb`] / [`FundedMwebPsbt::extract_tx`].
pub fn sign_funded_mweb(
    funded: &mut FundedMwebPsbt,
    _keys: &MasterKeys,
    secp: &Secp256k1<All>,
) -> Result<(), Error> {
    let mut outputs = Vec::with_capacity(funded.staged_outputs.len());
    let mut out_blinds = Vec::with_capacity(funded.staged_outputs.len());
    let mut out_keys = Vec::with_capacity(funded.staged_outputs.len());

    for staged in &funded.staged_outputs {
        let switched = blind_switch(&staged.raw_blind, staged.amount, secp)?;
        out_blinds.push(switched);
        out_keys.push(staged.sender_key);
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
        .map(|(spk, amt)| {
            Ok(PegOutCoin {
                amount: money_to_i64(*amt, "peg-out amount")?,
                script_pub_key: spk.clone(),
            })
        })
        .collect::<Result<_, Error>>()?;

    let kernel = create_kernel(
        kernel_blind,
        Some(stealth_blind),
        Some(money_to_i64(funded.fee, "kernel fee")?),
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

    inputs.sort_by_key(|a| a.output_id);
    outputs.sort_by_key(output_id);

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
    let stealth_by_commit: BTreeMap<[u8; 33], Vec<u8>> = funded
        .psbt
        .mweb_outputs
        .iter()
        .filter_map(|o| Some((*o.commit.as_ref()?, o.stealth_address.clone()?)))
        .collect();

    funded.psbt.mweb_tx_offset = Some(mw.kernel_offset);
    funded.psbt.mweb_stealth_offset = Some(mw.stealth_offset);
    funded.psbt.mweb_kernels = mw.body.kernels.iter().map(mweb_kernel_from_wire).collect();
    funded.psbt.mweb_outputs = mw.body.outputs.iter().map(mweb_output_from_wire).collect();
    funded.psbt.mweb_inputs = mw
        .body
        .inputs
        .iter()
        .map(|inp| {
            let mut mapped = mweb_input_from_wire(inp);
            if let Some(coin) = funded
                .spent_coins
                .iter()
                .find(|c| c.output_id == inp.output_id)
            {
                enrich_input_from_coin(&mut mapped, coin);
            }
            mapped
        })
        .collect();

    for out in &mut funded.psbt.mweb_outputs {
        if let Some(c) = out.commit {
            if let Some(sa) = stealth_by_commit.get(&c) {
                out.stealth_address = Some(sa.clone());
            }
        }
    }

    // Re-attach origins after remap (wire remap drops wallet metadata).
    crate::psbt::populate_mweb_key_origins(&mut funded.psbt, _keys, secp);
    // Validate before scrub clears address_index.
    crate::psbt::validate_mweb_key_origins_against(&funded.psbt, _keys)?;
    scrub_sensitive_fields(&mut funded.psbt);
    let _ = mw;
    Ok(())
}

/// Extract change coin from staged outputs after a successful sign (if any).
pub fn change_from_funded(
    funded: &FundedMwebPsbt,
    keys: &MasterKeys,
    secp: &Secp256k1<All>,
) -> Result<Option<MwebCoin>, Error> {
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

/// Funded peg-in (maps-first; `mw_tx` only at extract).
#[derive(Debug, Clone)]
pub struct FundedMwebPegin {
    /// Native PSBT carrying MWEB maps (initially empty transparent skeleton).
    pub psbt: Psbt,
    /// Staged receive output(s).
    pub staged_outputs: Vec<StagedMwebOutput>,
    /// Transparent v9 value (= kernel pegin amount).
    pub pegin_amount: u64,
    /// Kernel fee (litoshis).
    pub fee: u64,
    /// Receive address index for the owned stealth output.
    pub receive_index: u32,
    /// Set after [`sign_funded_mweb_pegin`] (= v9 witness program).
    pub kernel_id: Option<[u8; 32]>,
    /// Owned coins to insert after peg-in maturity (set after sign).
    pub outputs: Vec<MwebCoin>,
}

/// Fund an in-PSBT peg-in: stage output + unsigned peg-in kernel maps (no `mw_tx`).
pub fn fund_mweb_pegin(
    keys: &MasterKeys,
    receive_index: u32,
    pegin_amount: u64,
    fee: u64,
    network: impl Into<MwebHrp>,
    secp: &Secp256k1<All>,
) -> Result<FundedMwebPegin, Error> {
    let network = network.into();
    if pegin_amount <= fee {
        return Err(Error::InsufficientFunds);
    }
    let receive_amount = pegin_amount - fee;
    let addr = keys.address(receive_index, network, secp)?;
    let (raw_blind, sender_key, output) = create_output(&addr, receive_amount, secp)?;
    let mut mapped = mweb_output_from_wire(&output);
    mapped.stealth_address = Some(stealth_address_bytes(&addr)?);

    let mut features = KernelFeatures::PeginFeatureBit as u8;
    if fee > 0 {
        features |= KernelFeatures::FeeFeatureBit as u8;
    }
    features |= KernelFeatures::StealthExcessFeatureBit as u8;

    let kernel = MwebKernel {
        fee: (fee > 0).then_some(fee),
        pegin_amount: Some(pegin_amount),
        features: Some(features),
        ..MwebKernel::default()
    };

    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
        mw_tx: None,
        is_hog_ex: false,
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned)
        .map_err(|e| Error::Crypto(format!("psbt from_unsigned_tx: {e}")))?;
    psbt.mweb_inputs = Vec::new();
    psbt.mweb_outputs = vec![mapped];
    psbt.mweb_kernels = vec![kernel];
    psbt.mweb_tx_offset = None;
    psbt.mweb_stealth_offset = None;

    Ok(FundedMwebPegin {
        psbt,
        staged_outputs: vec![StagedMwebOutput {
            output,
            raw_blind,
            sender_key,
            amount: receive_amount,
            change_index: Some(receive_index),
        }],
        pegin_amount,
        fee,
        receive_index,
        kernel_id: None,
        outputs: Vec::new(),
    })
}

/// Sign a funded peg-in: create output/kernel, set offsets, compute `kernel_id`, scrub.
pub fn sign_funded_mweb_pegin(
    funded: &mut FundedMwebPegin,
    keys: &MasterKeys,
    secp: &Secp256k1<All>,
) -> Result<[u8; 32], Error> {
    let staged = funded
        .staged_outputs
        .first()
        .ok_or_else(|| Error::Crypto("peg-in missing staged output".into()))?
        .clone();

    let switched = blind_switch(&staged.raw_blind, staged.amount, secp)?;
    let kernel_offset = random_secret(secp);
    let kernel_blind = blind_sum(&[switched], &[kernel_offset])?;

    let stealth_blind = random_secret(secp);
    let stealth_offset = blind_sum(&[staged.sender_key], &[stealth_blind])?;

    let kernel = create_kernel(
        kernel_blind,
        Some(stealth_blind),
        Some(money_to_i64(funded.fee, "kernel fee")?),
        Some(money_to_i64(funded.pegin_amount, "peg-in amount")?),
        &[],
        secp,
    )?;
    let kid = crate::tx_builder::kernel_id(&kernel);

    let mut outputs = vec![staged.output.clone()];
    outputs.sort_by_key(output_id);

    let mw = MwebTransaction {
        kernel_offset,
        stealth_offset,
        body: TxBody {
            inputs: Vec::new(),
            outputs,
            kernels: vec![kernel],
        },
    };

    let stealth_by_commit: BTreeMap<[u8; 33], Vec<u8>> = funded
        .psbt
        .mweb_outputs
        .iter()
        .filter_map(|o| Some((*o.commit.as_ref()?, o.stealth_address.clone()?)))
        .collect();

    funded.psbt.mweb_tx_offset = Some(mw.kernel_offset);
    funded.psbt.mweb_stealth_offset = Some(mw.stealth_offset);
    funded.psbt.mweb_kernels = mw.body.kernels.iter().map(mweb_kernel_from_wire).collect();
    funded.psbt.mweb_outputs = mw.body.outputs.iter().map(mweb_output_from_wire).collect();
    funded.psbt.mweb_inputs = Vec::new();

    for out in &mut funded.psbt.mweb_outputs {
        if let Some(c) = out.commit {
            if let Some(sa) = stealth_by_commit.get(&c) {
                out.stealth_address = Some(sa.clone());
            }
        }
    }

    let ke = staged
        .output
        .message
        .standard_fields
        .as_ref()
        .ok_or(Error::Crypto("missing standard fields".into()))?
        .key_exchange_pubkey;
    let (t, spend) = crate::tx_builder::shared_secret_and_spend_for_owned(
        keys,
        funded.receive_index,
        &ke,
        &staged.output.receiver_public_key,
        secp,
    )?;
    funded.outputs = vec![MwebCoin {
        output_id: output_id(&staged.output),
        commitment: staged.output.commitment,
        amount: staged.amount,
        address_index: funded.receive_index,
        blind: staged.raw_blind,
        shared_secret: t,
        spend_key: Some(spend),
        block_height: None,
        is_pegin: true,
        leaf_index: None,
    }];
    funded.kernel_id = Some(kid);

    scrub_sensitive_fields(&mut funded.psbt);
    Ok(kid)
}
