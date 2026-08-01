//! F-Z05: P2P frame header validation.
//!
//! `TcpMwebPeer::recv` reads a 24-byte header and allocates the payload it declares
//! *before* anything authenticates that header. This target drives the extracted
//! framing logic directly, so the allocation guard is exercised without a socket.

use bdk_mweb::limits::MAX_P2P_PAYLOAD;
use bdk_mweb::lip0006_tcp::{frame_payload_len, parse_frame};
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;
use litecoin::Network;

fn do_test(data: &[u8]) {
    let mut c = Cursor::new(data);

    // Alternate between the network the peer claims and the one we expect, so the
    // fuzzer explores both the matching and mismatching magic paths.
    let magic = match c.u8() % 3 {
        0 => Network::Bitcoin.magic(),
        1 => Network::Testnet4.magic(),
        _ => Network::Regtest.magic(),
    };

    let mut header = [0u8; 24];
    let head = c.bytes(24);
    header[..head.len()].copy_from_slice(head);
    let payload = c.rest();

    match frame_payload_len(magic, &header) {
        Ok(len) => {
            assert!(
                len <= MAX_P2P_PAYLOAD,
                "accepted a frame declaring {len} bytes, above the cap"
            );
            // A header we accept must carry our magic; nothing else may pass.
            assert_eq!(header[..4], magic.to_bytes());
        }
        Err(e) => {
            // Every rejection must rotate the peer. A framing error that classified
            // as benign would leave the client stuck on a hostile peer, which is the
            // failure mode the substring-based classifier invites.
            assert!(
                bdk_mweb::mweb_sync::is_banworthy_peer_error(&e),
                "framing rejection is not banworthy: {e}"
            );
        }
    }

    // Full parse over the same bytes: must return, never panic, regardless of how
    // the declared length relates to the payload actually supplied.
    let _ = parse_frame(magic, &header, payload);
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
