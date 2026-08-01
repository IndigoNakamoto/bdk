//! F-Z09: `encrypt::open` against arbitrary bytes under an attacker-unknown key.
//!
//! Every sealed blob in a wallet directory is attacker-writable — that is the whole
//! threat model for encryption at rest. So the decoder has to treat its input as
//! hostile: truncation at any boundary, a magic that routes into the v2 parser with
//! a nonsense body, a length that makes the header and ciphertext overlap. None of
//! that may panic, and none of it may authenticate.
//!
//! The target also checks the two properties the v2 envelope exists to provide:
//! opening under the wrong `SealContext` fails, and a counter below the caller's
//! high-water mark fails.

use bdk_mweb::encrypt::{
    is_v2, open, open_with_context, open_with_context_at_least, seal,
    seal_with_context_and_counter, SealContext,
};
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;

fn context_of(tag: u8) -> SealContext {
    SealContext::from_tag(tag)
}

fn do_test(data: &[u8]) {
    let mut c = Cursor::new(data);
    let key = c.arr32();
    let ctx = context_of(c.u8());
    let min_counter = c.u64();
    let blob = c.rest();

    // Arbitrary bytes: must error, must not panic, must never authenticate under a
    // key the "attacker" did not know when the bytes were chosen.
    let _ = open(&key, blob);
    let _ = open_with_context(&key, blob, ctx);
    let _ = open_with_context_at_least(&key, blob, ctx, min_counter);

    // Prefixing the magic forces the v2 header parser instead of the legacy one,
    // which is where the length arithmetic lives.
    let mut magic_prefixed = b"MWEBSEAL".to_vec();
    magic_prefixed.extend_from_slice(blob);
    let _ = open(&key, &magic_prefixed);
    let _ = open_with_context(&key, &magic_prefixed, ctx);

    // Now the round-trip half: seal real plaintext and confirm the guarantees hold
    // for every mutation the fuzzer can express.
    let plaintext = blob;
    let counter = min_counter;

    let legacy = seal(&key, plaintext).expect("legacy seal");
    assert!(!is_v2(&legacy), "seal must keep writing the legacy format");
    assert_eq!(open(&key, &legacy).expect("legacy open"), plaintext);
    assert!(
        open_with_context(&key, &legacy, ctx).is_err(),
        "a legacy blob must not satisfy a context-checked open"
    );

    let v2 = seal_with_context_and_counter(&key, plaintext, ctx, counter).expect("v2 seal");
    assert!(is_v2(&v2));
    assert_eq!(open(&key, &v2).expect("v2 open"), plaintext);
    assert_eq!(
        open_with_context(&key, &v2, ctx).expect("v2 context open"),
        plaintext
    );
    let (pt, got_counter) =
        open_with_context_at_least(&key, &v2, ctx, counter).expect("v2 counter open");
    assert_eq!(pt, plaintext);
    assert_eq!(got_counter, counter);

    // Wrong context must fail. Every other tag is a different context by definition.
    let other = context_of(ctx.tag().wrapping_add(1));
    assert!(
        open_with_context(&key, &v2, other).is_err(),
        "cross-context open succeeded: {} accepted as {}",
        ctx.tag(),
        other.tag()
    );

    // Rollback must fail: any counter above what was sealed is a stale file.
    if let Some(higher) = counter.checked_add(1) {
        assert!(
            open_with_context_at_least(&key, &v2, ctx, higher).is_err(),
            "a counter below the high-water mark was accepted"
        );
    }

    // Truncation at every boundary in the header, plus a few in the body.
    for len in 0..v2.len().min(64) {
        assert!(
            open(&key, &v2[..len]).is_err(),
            "truncation to {len} opened"
        );
        assert!(open_with_context(&key, &v2[..len], ctx).is_err());
    }

    // Single-byte edits: the header is AAD, the rest is ciphertext and tag. Both
    // must be caught, and the header edits must be caught even though they are not
    // encrypted.
    for i in 0..v2.len().min(96) {
        let mut bad = v2.clone();
        bad[i] ^= 0x01;
        assert!(
            open(&key, &bad).is_err(),
            "byte {i} of a v2 envelope could be edited undetected"
        );
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

    #[test]
    fn sweep_pseudorandom_corpus() {
        // Fewer iterations than the decode targets: each one performs two AEAD
        // seals plus ~160 opens.
        bdk_mweb_fuzz::sweep(100, super::do_test);
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
