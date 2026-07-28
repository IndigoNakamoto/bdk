//! Ingest Go-generated ltcd PSBT / kernel fixtures (see `tests/fixtures/` +
//! `scripts/ltcd_mweb_fixtures`).

use bdk_mweb::psbt::extract_tx_with_mweb;
use bdk_mweb::psbt_from_ltcd_v2;
use bitcoin::consensus::serialize;
use bitcoin::psbt::mweb::MwebKernel;
use hex_conservative::FromHex;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn fixture_hex(name: &str) -> Vec<u8> {
    let s = String::from_utf8(fixture_bytes(name))
        .unwrap()
        .trim()
        .to_string();
    <Vec<u8>>::from_hex(&s).unwrap()
}

fn fixture_b64(name: &str) -> Vec<u8> {
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
    let s = String::from_utf8(fixture_bytes(name))
        .unwrap()
        .trim()
        .to_string();
    BASE64_STANDARD.decode(s).expect("base64")
}

#[test]
fn go_signed_psbt_extracts_matching_tx() {
    let psbt_bytes = fixture_b64("psbt_sign_mweb_signed.base64");
    let psbt = psbt_from_ltcd_v2(&psbt_bytes).expect("ingest Go-signed PSBTv2");
    assert!(!psbt.mweb_inputs.is_empty());
    assert!(!psbt.mweb_outputs.is_empty());
    assert!(!psbt.mweb_kernels.is_empty());
    assert!(psbt.mweb_tx_offset.is_some());
    assert!(psbt.mweb_stealth_offset.is_some());

    let tx = extract_tx_with_mweb(&psbt).expect("extract");
    let mw = tx.mw_tx.as_ref().expect("mw_tx");
    assert_eq!(mw.body.inputs.len(), 1);
    assert_eq!(mw.body.outputs.len(), 1);
    assert_eq!(mw.body.kernels.len(), 1);

    let want = fixture_hex("psbt_sign_mweb_extracted.hex");
    let got = serialize(&tx);
    assert_eq!(
        got, want,
        "Rust extract of Go-signed PSBT must match Go Extract wire bytes"
    );
}

#[test]
fn go_unsigned_psbt_deserializes_and_has_stealth() {
    let psbt_bytes = fixture_b64("psbt_sign_mweb_unsigned.base64");
    let psbt = psbt_from_ltcd_v2(&psbt_bytes).expect("ingest Go-unsigned PSBTv2");
    assert_eq!(psbt.mweb_inputs.len(), 1);
    assert_eq!(psbt.mweb_outputs.len(), 1);
    assert_eq!(psbt.mweb_kernels.len(), 1);
    assert!(psbt.mweb_tx_offset.is_none());
    assert_eq!(
        psbt.mweb_outputs[0]
            .stealth_address
            .as_ref()
            .map(|a| a.len()),
        Some(66)
    );
    assert!(psbt.mweb_inputs[0].amount.is_some());
    assert!(psbt.mweb_inputs[0].key_exchange_pubkey.is_some());
}

#[test]
fn go_extract_valid_mweb_psbt() {
    let psbt_bytes = fixture_b64("psbt_extract_valid_mweb.base64");
    let psbt = psbt_from_ltcd_v2(&psbt_bytes).expect("ingest");
    let tx = extract_tx_with_mweb(&psbt).expect("extract minimal finalized");
    let mw = tx.mw_tx.as_ref().unwrap();
    assert_eq!(mw.body.inputs.len(), 1);
    assert_eq!(mw.body.outputs.len(), 1);
    assert_eq!(mw.body.kernels.len(), 1);
}

#[test]
fn kernel_all_fields_roundtrip() {
    let raw = fixture_hex("kernel_all_fields.hex");
    let pk = MwebKernel::deserialize_ltcd_map(&raw).expect("deserialize_ltcd_map");
    assert!(pk.excess_commit.is_some());
    assert!(pk.stealth_commit.is_some());
    assert_eq!(pk.fee, Some(10_000));
    assert_eq!(pk.pegin_amount, Some(20_000));
    assert_eq!(pk.pegouts.len(), 2);
    assert_eq!(pk.lock_height, Some(150));
    assert_eq!(pk.features, Some(0x3f));
    assert_eq!(pk.extra_data.as_deref(), Some(b"extra data".as_slice()));
    assert!(pk.signature.is_some());

    let pairs = pk.to_pairs();
    let back = MwebKernel::from_pairs(pairs);
    assert_eq!(back.fee, pk.fee);
    assert_eq!(back.features, pk.features);
    assert_eq!(back.excess_commit, pk.excess_commit);
    assert_eq!(back.stealth_commit, pk.stealth_commit);
    assert_eq!(back.pegouts, pk.pegouts);
}
