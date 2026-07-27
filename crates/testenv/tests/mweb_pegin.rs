//! Regtest acceptance: Core finalize path for MWEB peg-in (Phase 1).
//!
//! Requires `LITECOIND_EXE`. Skips cleanly when unset.

#![cfg(feature = "litecoin-daemon")]

use bdk_chain::bitcoin::consensus::encode::serialize_hex;
use bdk_chain::bitcoin::Amount;
use bdk_chain::{is_mweb_bridge_output, mweb_pegin_script_pubkey};
use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};

#[test]
fn core_finalize_pegin_recognized_after_maturity() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };

    let mining = env.mine_to_pre_mweb().expect("pre-mweb mine");
    let mweb = env.rpc.get_new_mweb_address().expect("mweb addr");
    assert!(
        mweb.to_string().starts_with("tmweb1"),
        "regtest MWEB HRP, got {mweb}"
    );

    let peg_amount = Amount::from_btc(1.0).unwrap();
    let tx = env
        .finalize_mweb_pegin(&mweb, peg_amount)
        .expect("Core peg-in finalize");

    assert!(
        tx.mw_tx.is_some(),
        "peg-in must carry an mw_tx body: {}",
        serialize_hex(&tx)
    );
    assert!(!tx.is_hog_ex);

    let pegin_out = tx
        .output
        .iter()
        .find(|o| {
            is_mweb_bridge_output(&o.script_pubkey)
                && o.script_pubkey.witness_version()
                    == Some(
                        bdk_chain::bitcoin::blockdata::script::witness_version::WitnessVersion::V9,
                    )
        })
        .expect("witness v9 peg-in output");

    let program = pegin_out.script_pubkey.as_bytes();
    // OP_9 (0x59) + push32 (0x20) + 32-byte kernel id
    assert_eq!(program[0], 0x59);
    assert_eq!(program[1], 0x20);
    let mut kernel = [0u8; 32];
    kernel.copy_from_slice(&program[2..34]);
    assert_eq!(
        mweb_pegin_script_pubkey(&kernel),
        pegin_out.script_pubkey,
        "helper must reproduce Core's peg-in script"
    );

    env.mine_mweb_activation(&mining).expect("activate mweb");
    env.mine_blocks(MWEB_PEGIN_MATURITY.saturating_sub(1), &mining)
        .expect("maturity");

    let received = env
        .rpc
        .list_received_by_mweb_address(&mweb, MWEB_PEGIN_MATURITY)
        .expect("listreceived");
    assert_eq!(
        received, peg_amount,
        "Core must credit the MWEB address after maturity"
    );
}
