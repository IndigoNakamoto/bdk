//! Ingest ltcd PSBTv2 MWEB packets into rust-litecoin [`Psbt`] maps.
//!
//! ltcd serializes pure-MWEB PSBTs as BIP370 v2 (global version + input/output/kernel
//! map sections). rust-litecoin currently round-trips MWEB on PSBTv0 with indexed
//! global keys. This module bridges Go-produced bytes so BDK can extract / validate
//! without requiring a Go toolchain at test time.

use alloc::vec::Vec;

use bitcoin::blockdata::transaction;
use bitcoin::psbt::mweb::{MwebInput, MwebKernel, MwebOutput};
use bitcoin::psbt::Psbt;
use bitcoin::Transaction;

use crate::error::Error;

const PSBT_MAGIC: &[u8] = b"psbt\xff";
const GLOBAL_VERSION: u8 = 0xFB;
const GLOBAL_TX_VERSION: u8 = 0x02;
const GLOBAL_INPUT_COUNT: u8 = 0x04;
const GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const GLOBAL_MWEB_TX_OFFSET: u8 = 0x90;
const GLOBAL_MWEB_STEALTH_OFFSET: u8 = 0x91;
const GLOBAL_MWEB_KERNEL_COUNT: u8 = 0x92;

/// Deserialize an ltcd PSBTv2 (MWEB) packet into a rust-litecoin [`Psbt`].
///
/// Transparent vin/vout are left empty (pure-MWEB packets). MWEB maps are filled
/// from the v2 input / output / kernel sections.
pub fn psbt_from_ltcd_v2(bytes: &[u8]) -> Result<Psbt, Error> {
    if bytes.len() < 5 || &bytes[..5] != PSBT_MAGIC {
        return Err(Error::Crypto("ltcd PSBT: bad magic".into()));
    }
    let mut r = &bytes[5..];

    let mut version = 0u32;
    let mut tx_version = 2u32;
    let mut input_count = 0usize;
    let mut output_count = 0usize;
    let mut kernel_count = 0usize;
    let mut mweb_tx_offset = None;
    let mut mweb_stealth_offset = None;

    loop {
        let (key, value, rest) = read_kv(r)?;
        r = rest;
        if key.is_empty() {
            break; // global separator
        }
        let ty = key[0];
        let key_data = &key[1..];
        match ty {
            GLOBAL_VERSION if key_data.is_empty() && value.len() == 4 => {
                version = u32::from_le_bytes(value.try_into().unwrap());
            }
            GLOBAL_TX_VERSION if key_data.is_empty() && value.len() == 4 => {
                tx_version = u32::from_le_bytes(value.try_into().unwrap());
            }
            GLOBAL_INPUT_COUNT if key_data.is_empty() => {
                input_count = read_varint(value)? as usize;
            }
            GLOBAL_OUTPUT_COUNT if key_data.is_empty() => {
                output_count = read_varint(value)? as usize;
            }
            GLOBAL_MWEB_KERNEL_COUNT if key_data.is_empty() => {
                kernel_count = read_varint(value)? as usize;
            }
            GLOBAL_MWEB_TX_OFFSET if key_data.is_empty() && value.len() == 32 => {
                let mut off = [0u8; 32];
                off.copy_from_slice(value);
                mweb_tx_offset = Some(off);
            }
            GLOBAL_MWEB_STEALTH_OFFSET if key_data.is_empty() && value.len() == 32 => {
                let mut off = [0u8; 32];
                off.copy_from_slice(value);
                mweb_stealth_offset = Some(off);
            }
            _ => {} // ignore other globals (fallback locktime, etc.)
        }
    }

    if version != 2 {
        return Err(Error::Crypto(format!(
            "ltcd PSBT: expected version 2, got {version}"
        )));
    }

    let mut mweb_inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let (map, rest) = read_map_section(r)?;
        r = rest;
        let mut inp = MwebInput::default();
        for (ty, key_data, value) in map {
            inp.apply_kv_field(ty, &key_data, &value);
        }
        mweb_inputs.push(inp);
    }

    let mut mweb_outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let (map, rest) = read_map_section(r)?;
        r = rest;
        let mut out = MwebOutput::default();
        for (ty, key_data, value) in map {
            if !key_data.is_empty() {
                continue;
            }
            out.apply_field(ty, &value);
        }
        mweb_outputs.push(out);
    }

    let mut mweb_kernels = Vec::with_capacity(kernel_count);
    for _ in 0..kernel_count {
        let (map, rest) = read_map_section(r)?;
        r = rest;
        // Kernel maps: type byte is the field type; key may hold pegout index.
        let mut encoded = Vec::new();
        for (ty, key_data, value) in &map {
            // Re-encode as ltcd kernel map bytes for deserialize_ltcd_map.
            write_varbytes(&mut encoded, &[&[*ty], key_data.as_slice()].concat());
            write_varbytes(&mut encoded, value);
        }
        encoded.push(0x00);
        let k = MwebKernel::deserialize_ltcd_map(&encoded)
            .map_err(|e| Error::Crypto(format!("kernel map: {e}")))?;
        mweb_kernels.push(k);
    }

    if !r.is_empty() {
        return Err(Error::Crypto(format!(
            "ltcd PSBT: {} trailing bytes",
            r.len()
        )));
    }

    Ok(Psbt {
        unsigned_tx: Transaction {
            version: transaction::Version(tx_version as i32),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
            mw_tx: None,
            is_hog_ex: false,
        },
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: vec![],
        outputs: vec![],
        mweb_tx_offset,
        mweb_stealth_offset,
        mweb_kernels,
        mweb_inputs,
        mweb_outputs,
    })
}

fn read_map_section(mut r: &[u8]) -> Result<(Vec<(u8, Vec<u8>, Vec<u8>)>, &[u8]), Error> {
    let mut pairs = Vec::new();
    loop {
        let (key, value, rest) = read_kv(r)?;
        r = rest;
        if key.is_empty() {
            break;
        }
        pairs.push((key[0], key[1..].to_vec(), value.to_vec()));
    }
    Ok((pairs, r))
}

fn read_kv(r: &[u8]) -> Result<(&[u8], &[u8], &[u8]), Error> {
    let (key, r) = read_varbytes(r)?;
    if key.is_empty() {
        return Ok((key, &[], r));
    }
    let (value, r) = read_varbytes(r)?;
    Ok((key, value, r))
}

fn read_varbytes(r: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len, r) = read_varint_slice(r)?;
    let len = len as usize;
    if r.len() < len {
        return Err(Error::Crypto("ltcd PSBT: truncated varbytes".into()));
    }
    Ok((&r[..len], &r[len..]))
}

fn read_varint(value: &[u8]) -> Result<u64, Error> {
    let (n, rest) = read_varint_slice(value)?;
    if !rest.is_empty() {
        return Err(Error::Crypto("ltcd PSBT: trailing varint bytes".into()));
    }
    Ok(n)
}

fn read_varint_slice(r: &[u8]) -> Result<(u64, &[u8]), Error> {
    if r.is_empty() {
        return Err(Error::Crypto("ltcd PSBT: empty varint".into()));
    }
    let n = r[0] as u64;
    if n < 0xfd {
        return Ok((n, &r[1..]));
    }
    if n == 0xfd {
        if r.len() < 3 {
            return Err(Error::Crypto("ltcd PSBT: truncated varint16".into()));
        }
        let v = u16::from_le_bytes([r[1], r[2]]) as u64;
        return Ok((v, &r[3..]));
    }
    if n == 0xfe {
        if r.len() < 5 {
            return Err(Error::Crypto("ltcd PSBT: truncated varint32".into()));
        }
        let v = u32::from_le_bytes(r[1..5].try_into().unwrap()) as u64;
        return Ok((v, &r[5..]));
    }
    if r.len() < 9 {
        return Err(Error::Crypto("ltcd PSBT: truncated varint64".into()));
    }
    let v = u64::from_le_bytes(r[1..9].try_into().unwrap());
    Ok((v, &r[9..]))
}

fn write_varbytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= u16::MAX as u64 {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}
