//! F-Z04: `getmwebutxos` decode.
//!
//! This is the request we send rather than a response we receive, but it shares the
//! codec, and a wallet acting as a server (or a test harness replaying a capture)
//! decodes it from untrusted bytes.

use bdk_mweb::p2p::GetMwebUtxos;
use honggfuzz::fuzz;
use litecoin::consensus::encode::{deserialize, serialize};

fn do_test(data: &[u8]) {
    let Ok(decoded) = deserialize::<GetMwebUtxos>(data) else {
        return;
    };
    assert_eq!(
        serialize(&decoded),
        data,
        "getmwebutxos round-trip changed bytes"
    );
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
        bdk_mweb_fuzz::sweep(2000, super::do_test);
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
