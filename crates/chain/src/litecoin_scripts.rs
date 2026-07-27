//! Litecoin-specific script helpers for the transparent indexer and peg-in construction.
//!
//! MWEB bridge outputs on the canonical chain use dedicated witness versions that must never be
//! treated as ordinary spendable UTXOs by a transparent wallet:
//!
//! - **v8** — HogAddr (HogEx integration balance; not user-spendable)
//! - **v9** — MWEB peg-in (`WITNESS_MWEB_PEGIN`; funds enter the extension block)
//!
//! Peg-out destinations in HogEx transactions use normal p2wpkh/p2tr scripts and **must** still be
//! indexed when they match a watched script pubkey.
//!
//! A peg-in's 32-byte witness program is the peg-in **kernel id** (see `docs/MWEB_PEGIN.md`).

use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::{Script, ScriptBuf};

/// Returns `true` if `script` is a Litecoin MWEB bridge output (witness v8 HogAddr or v9 peg-in).
pub fn is_mweb_bridge_output(script: &Script) -> bool {
    match script.witness_version() {
        Some(WitnessVersion::V8) | Some(WitnessVersion::V9) => true,
        _ => false,
    }
}

/// Builds the transparent peg-in `scriptPubKey`: witness version 9 committing to `kernel_id`.
///
/// The matching transaction must also carry an `mw_tx` whose peg-in kernel id equals `kernel_id`.
/// Authoring that kernel is outside this crate (litecoind / mwebd).
pub fn mweb_pegin_script_pubkey(kernel_id: &[u8; 32]) -> ScriptBuf {
    let program = WitnessProgram::new(WitnessVersion::V9, kernel_id)
        .expect("32-byte v9 program is always valid");
    ScriptBuf::new_witness_program(&program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use bitcoin::blockdata::script::witness_program::WitnessProgram;
    use bitcoin::blockdata::script::witness_version::WitnessVersion;
    use bitcoin::hex::FromHex;
    use bitcoin::ScriptBuf;

    #[test]
    fn detects_v8_and_v9_bridge_programs() {
        let prog32 = [0x11u8; 32];
        let v8 = WitnessProgram::new(WitnessVersion::V8, &prog32).unwrap();
        let v9 = WitnessProgram::new(WitnessVersion::V9, &prog32).unwrap();
        let spk_v8 = ScriptBuf::new_witness_program(&v8);
        let spk_v9 = ScriptBuf::new_witness_program(&v9);
        assert!(is_mweb_bridge_output(&spk_v8));
        assert!(is_mweb_bridge_output(&spk_v9));
    }

    #[test]
    fn ignores_ordinary_segwit() {
        let p2wpkh = ScriptBuf::from_hex(
            "00147f91924ca69474ef38b06884d1762fdbdc440265",
        )
        .unwrap();
        assert!(!is_mweb_bridge_output(&p2wpkh));
    }

    #[test]
    fn pegin_script_matches_regtest_vector() {
        use bitcoin::hex::DisplayHex;

        // docs/MWEB_PEGIN.md — kernel_id from Core decoderawtransaction.vkern[0]
        let kernel = <[u8; 32]>::try_from(
            Vec::from_hex("a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let spk = mweb_pegin_script_pubkey(&kernel);
        assert_eq!(
            spk.as_bytes().to_lower_hex_string(),
            "5920a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a"
        );
        assert!(is_mweb_bridge_output(&spk));
    }
}
