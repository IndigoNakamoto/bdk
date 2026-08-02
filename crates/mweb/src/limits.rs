//! Bounds applied to peer-supplied data before it is allocated or iterated.
//!
//! Everything in a LIP-0006 payload is attacker-controlled, including the length
//! prefixes. Decoders must reject an implausible length *before* allocating for it:
//! a `Vec` allocation that fails calls `handle_alloc_error`, which aborts the
//! process rather than unwinding, so an unbounded length prefix is a remote crash
//! and not merely an error path.
//!
//! The constants below are derived from the wire protocol rather than picked, so
//! they can be re-derived when the protocol changes:
//!
//! - A leafset arrives in a single P2P message, so it cannot exceed the message cap.
//! - The output MMR cannot hold more leaves than the largest deliverable leafset has bits.
//! - A batch cannot hold more UTXOs than `getmwebutxos.num_requested` can express.

/// Largest P2P message payload accepted from a peer, in bytes.
///
/// Litecoin's `MAX_PROTOCOL_MESSAGE_LENGTH` is 32 MB (`net.h`) — eight times
/// Bitcoin Core's 4 MB, raised because MWEB payloads are large. That is the limit
/// litecoind enforces on *receive*, so an honest peer never sends more. This cap
/// is Core's `MAX_SIZE` (32 MiB), just above it, so a protocol change cannot
/// silently break live sync while a single allocation stays bounded.
pub const MAX_P2P_PAYLOAD: usize = 32 * 1024 * 1024;

/// Largest `mwebleafset` bitset accepted, in bytes.
///
/// Deliberately far tighter than the 32 MB the protocol would allow, because the
/// leafset also sizes the index vectors built by
/// [`crate::p2p::MwebLeafset::unspent_leaf_indices`]. 4 MB is one bit per leaf for
/// 32 million leaves against roughly 350 thousand on mainnet today, so this is a
/// policy choice with ~90x headroom rather than a bound derived from the wire.
pub const MAX_LEAFSET_BYTES: usize = 4_000_000;

/// Largest `output_mmr_size` accepted from a peer's MWEB header.
///
/// Verification requires a leafset with one bit per leaf ([`crate::pmmr::verify_leafset`]),
/// so an MMR larger than [`MAX_LEAFSET_BYTES`] bits could not have its leafset
/// delivered in the first place. Any larger value is unusable and is rejected
/// before it can size a loop.
pub const MAX_OUTPUT_MMR_SIZE: u64 = (MAX_LEAFSET_BYTES as u64) * 8;

/// Largest number of UTXO entries accepted in one `mwebutxos` message.
///
/// `GetMwebUtxos::num_requested` is a `u16`, so an honest peer cannot answer with
/// more entries than this no matter what was asked for.
///
/// This bounds what a peer may *send* us, and so is derived from the wire field.
/// [`MAX_REQUESTED_MWEB_UTXOS`] bounds what we may *ask* for, and is smaller.
pub const MAX_UTXOS_PER_BATCH: usize = u16::MAX as usize;

/// Largest `num_requested` litecoind will honour in a `getmwebutxos`.
///
/// Core's `MAX_REQUESTED_MWEB_UTXOS` (`net_processing.cpp`). Asking for more is
/// not merely wasted: litecoind **disconnects** the peer. Requests are clamped to
/// this before they go on the wire.
///
/// Requesting the maximum matters more since 0.21.5.6, where serving is
/// rate-limited per *request* rather than per UTXO, so a wider batch buys
/// proportionally more data per token. A full 4096-entry batch is roughly 3.8 MB
/// of `FULL` outputs, comfortably inside both Litecoin's 32 MB message limit and
/// [`MAX_P2P_PAYLOAD`].
pub const MAX_REQUESTED_MWEB_UTXOS: u16 = 4096;

/// Largest number of segment `parent_hashes` accepted in one `mwebutxos` message.
///
/// A segment proof carries at most one pruned parent per MMR node spanned by the
/// batch (two nodes per leaf) plus one peak chain, which is bounded by the 64-bit
/// position space.
pub const MAX_PARENT_HASHES: usize = 2 * MAX_UTXOS_PER_BATCH + 64;

/// Largest litoshi amount that can exist: Litecoin's `MAX_MONEY` (84M LTC).
///
/// Consensus rejects any amount outside `[0, MAX_MONEY]` (Core `MoneyRange`), so
/// a rewound or peer-supplied amount above this is fabricated by construction.
/// Amounts bounded by this constant also cannot wrap when cast to the `i64`
/// kernel-amount representation.
pub const MAX_MONEY: u64 = 84_000_000 * 100_000_000;

/// Upper bound on a single `reserve` when decoding a peer-supplied sequence.
///
/// Length prefixes are capped before use, but a capped length is still far larger
/// than a typical message. Reserving in chunks keeps the allocation proportional to
/// what the peer actually delivers instead of what it claims.
#[cfg_attr(not(feature = "lip0006"), allow(dead_code))]
pub(crate) const RESERVE_CHUNK: usize = 1024;

/// Litecoin mainnet was near 350k MWEB leaves in mid-2026 (`docs/LITECOIN_E2E.md`).
/// The caps must stay far enough above that to never become the binding constraint
/// on live sync before someone revisits them.
// Used only by the const assertions below; rustc before 1.93 does not count a use
// inside an anonymous `const _` as a use, so the MSRV build needs this.
#[allow(dead_code)]
const OBSERVED_MAINNET_LEAVES: u64 = 350_000;

// These relationships are the derivation, not incidental values. Checking them at
// compile time means a future edit to one constant cannot silently invalidate
// another.
const _: () = {
    // The MMR ceiling is exactly what the leafset cap can address; if they drift,
    // one of the two is unreachable.
    assert!(MAX_OUTPUT_MMR_SIZE == (MAX_LEAFSET_BYTES as u64) * 8);
    // A leafset arrives as a single message.
    assert!(MAX_LEAFSET_BYTES <= MAX_P2P_PAYLOAD);
    // `num_requested` is a `u16`, so an honest peer cannot exceed this.
    assert!(MAX_UTXOS_PER_BATCH == u16::MAX as usize);
    // What we ask for must be something a peer is allowed to answer in full.
    assert!(MAX_REQUESTED_MWEB_UTXOS as usize <= MAX_UTXOS_PER_BATCH);
    // At least 50x headroom over observed mainnet usage.
    assert!(MAX_OUTPUT_MMR_SIZE > OBSERVED_MAINNET_LEAVES * 50);
    assert!(MAX_LEAFSET_BYTES as u64 > (OBSERVED_MAINNET_LEAVES / 8) * 50);
    // Kernel amounts are i64 on the wire; the cast in the tx builders relies on this.
    assert!(MAX_MONEY <= i64::MAX as u64);
};
