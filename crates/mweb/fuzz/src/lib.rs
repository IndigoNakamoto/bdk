//! Shared helpers for the `bdk_mweb` fuzz targets.
//!
//! Most of these targets need *structured* input (a leafset plus a root plus an MMR
//! size, say) rather than one opaque byte string. [`Cursor`] carves the fuzzer's
//! bytes into typed fields without pulling in `arbitrary`, keeping the harness
//! dependency-light and the field layout obvious when reproducing a crash by hand.

/// A byte reader that yields defaults instead of failing once input runs out.
///
/// Fuzz targets must not reject inputs for being short: an early `return` on a
/// truncated input teaches the fuzzer that short inputs are uninteresting and
/// starves the deeper code paths. Running off the end here just produces zeros, so
/// every input drives the target to completion.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a fuzzer-provided buffer.
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Next byte, or 0 once exhausted.
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    /// Next little-endian `u16`, zero-padded once exhausted.
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    /// Next little-endian `u32`, zero-padded once exhausted.
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    /// Next little-endian `u64`, zero-padded once exhausted.
    pub fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        for slot in b.iter_mut() {
            *slot = self.u8();
        }
        u64::from_le_bytes(b)
    }

    /// Next 32 bytes, zero-padded once exhausted.
    pub fn arr32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for slot in b.iter_mut() {
            *slot = self.u8();
        }
        b
    }

    /// Everything not yet consumed.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        out
    }

    /// Up to `max` bytes, however many remain.
    pub fn bytes(&mut self, max: usize) -> &'a [u8] {
        // `u8` saturates `pos` past the end once input is exhausted, so clamp before
        // slicing rather than assuming `pos` is in bounds.
        let start = self.pos.min(self.data.len());
        let take = max.min(self.data.len() - start);
        let out = &self.data[start..start + take];
        self.pos = start + take;
        out
    }

    /// Whether any input remains. Useful to bound a repeat loop by real input
    /// rather than by a fuzzer-chosen count, which keeps runtime proportional to
    /// the corpus entry.
    pub fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }
}

/// Drive `f` over a deterministic pseudorandom corpus.
///
/// honggfuzz needs libunwind and binutils 2.38, which is a real barrier on
/// developer machines and in CI. Without something like this, a target's assertions
/// are never executed on non-trivial input and can rot into always-true or
/// always-panicking without anyone noticing. Each target calls this from a test, so
/// `cargo test` alone proves the invariants are both reachable and satisfied.
///
/// This is a smoke test, not a substitute for fuzzing: it explores a fixed corpus
/// with no coverage feedback.
pub fn sweep(iterations: u32, f: impl Fn(&[u8])) {
    // xorshift64*, so the corpus is identical on every machine and a failure
    // reproduces from the iteration number alone.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    for i in 0..iterations {
        // Vary length as well as content: several targets branch on running out of
        // input, and a fixed length would never reach those paths.
        let len = (next() % 512) as usize;
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            buf.extend_from_slice(&next().to_le_bytes());
        }
        buf.truncate(len);
        // Interleave low-entropy inputs: structured decoders reject high-entropy
        // bytes almost immediately, so all-zero and all-one runs reach deeper.
        if i % 4 == 0 {
            buf.iter_mut().for_each(|b| *b = 0);
        } else if i % 7 == 0 {
            buf.iter_mut().for_each(|b| *b = 0xFF);
        }
        f(&buf);
    }
}

/// Decode a hex string into `out`, for pasting a honggfuzz crash back into a test.
///
/// Mirrors the helper in `rust-litecoin/fuzz` so a crash reproduces the same way in
/// both harnesses.
pub fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
    let mut b = 0;
    for (idx, c) in hex.as_bytes().iter().enumerate() {
        b <<= 4;
        match *c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => panic!("Bad hex"),
        }
        if (idx & 1) == 1 {
            out.push(b);
            b = 0;
        }
    }
}
