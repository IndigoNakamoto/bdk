//! F-Z08: `rewind_output` on attacker-controlled outputs against a fixed keyset.
//!
//! During sync every downloaded output is fed to the rewind path *before* any
//! ownership is established, so this function runs on fully hostile input. Two
//! properties are asserted:
//!
//! 1. It never panics, whatever the output contains.
//! 2. It never yields a coin: the fuzzer does not hold the wallet's scan key, so producing an
//!    output that passes the view-tag, commitment, and key-exchange checks would mean ownership can
//!    be forged without the key.
//!
//! Two input shapes are driven from the same bytes: a consensus-decode of the
//! raw buffer (the wire boundary), and a structured build via [`Cursor`] with
//! valid pubkeys and `standard_fields` present, which reaches past the feature
//! gate into the view-tag and (with feature `zkp`) commitment arithmetic.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::scan::{rewind_output, AddressBook};
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;
use litecoin::blockdata::mimblewimble::{Output, OutputMessage, OutputMessageStandardFields};
use litecoin::consensus::encode::deserialize;
use litecoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use litecoin::Network;
use std::sync::OnceLock;

/// Fixed wallet keyset. The seed is public, but the fuzzer's byte budget cannot
/// perform the ECDH needed to target it, so a yielded coin is a real forgery.
fn keyset() -> &'static (Secp256k1<All>, MasterKeys, AddressBook) {
    static KEYS: OnceLock<(Secp256k1<All>, MasterKeys, AddressBook)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let secp = Secp256k1::new();
        let keys = MasterKeys::from_seed(
            &[0x42u8; 32],
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
        .expect("fixed seed");
        let book = AddressBook::from_keys(&keys, 8, &secp).expect("address book");
        (secp, keys, book)
    })
}

fn pubkey_from(c: &mut Cursor) -> Option<PublicKey> {
    let sk = SecretKey::from_slice(&c.arr32()).ok()?;
    Some(PublicKey::from_secret_key(&Secp256k1::new(), &sk))
}

fn structured_output(c: &mut Cursor) -> Option<Output> {
    let ke = pubkey_from(c)?;
    let sender = pubkey_from(c)?;
    let receiver = pubkey_from(c)?;
    let mut commitment = [0u8; 33];
    commitment[..32].copy_from_slice(&c.arr32());
    commitment[32] = c.u8() % 2 + 8; // plausible Pedersen prefix (0x08/0x09)
    let mut masked_nonce = [0u8; 16];
    masked_nonce.copy_from_slice(&c.arr32()[..16]);
    let mut range_proof = [0u8; 675];
    range_proof[..32].copy_from_slice(&c.arr32());
    Some(Output {
        commitment,
        sender_public_key: sender,
        receiver_public_key: receiver,
        message: OutputMessage {
            // Bit 0x01 set so `standard_fields` is actually consulted.
            features: c.u8() | 0x01,
            standard_fields: Some(OutputMessageStandardFields {
                key_exchange_pubkey: ke,
                view_tag: c.u8(),
                masked_value: c.u64(),
                masked_nonce,
            }),
            extra_data: Vec::new(),
        },
        range_proof,
        signature: [0u8; 64],
    })
}

fn assert_no_coin(output: &Output) {
    let (secp, keys, book) = keyset();
    match rewind_output(keys, book, output, secp) {
        Ok(Some(coin)) => panic!(
            "rewind yielded a coin for a fabricated output: amount={} index={}",
            coin.amount, coin.address_index
        ),
        // `Ok(None)` (not ours) and `Err` (e.g. ZkpDisabled without the zkp
        // feature, or the MAX_MONEY fail-closed path) are both fine — the
        // properties are "no panic" and "no coin".
        Ok(None) | Err(_) => {}
    }
}

fn do_test(data: &[u8]) {
    // Shape 1: the wire boundary — arbitrary bytes as a consensus-encoded Output.
    if let Ok(output) = deserialize::<Output>(data) {
        assert_no_coin(&output);
    }

    // Shape 2: structured build, so the view-tag branch and beyond are reachable.
    let mut c = Cursor::new(data);
    if let Some(output) = structured_output(&mut c) {
        assert_no_coin(&output);
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    use bdk_mweb_fuzz::extend_vec_from_hex;

    /// Exercise the target's assertions over a deterministic pseudorandom corpus,
    /// so they are verified by `cargo test` even where honggfuzz is unavailable.
    #[test]
    fn sweep_pseudorandom_corpus() {
        bdk_mweb_fuzz::sweep(500, super::do_test);
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
