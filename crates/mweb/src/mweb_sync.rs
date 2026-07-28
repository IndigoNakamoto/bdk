//! mwebsync-shaped LIP-0006 syncer (differential leafset + UTXO dating).
//!
//! Flow (one pass):
//! `WaitHeaders → SampleFineHeaders → VerifyTip → DiffLeafset → FetchAdded → Scan → PersistState`
//!
//! Continuous looping is [`MwebSyncer::run_loop`]; header wait is supplied by the caller
//! via [`SyncNotifier`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use bitcoin::blockdata::block::BlockHash;
use bitcoin::blockdata::mimblewimble::Output;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;

use crate::coin_db::MwebCoinDatabase;
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::lip0006::{verify_parent_hashes_present, MwebUtxoSource, SyncResult, VerifyMode, DEFAULT_UTXO_BATCH};
use crate::p2p::{GetMwebUtxos, OUTPUT_FORMAT_FULL};
use crate::pmmr::{verify_leafset, verify_utxo_batch};
use crate::scan::{scan_utxo_entries_at, AddressBook};

/// Fine stratified window: sample every height in the last N blocks (matches mwebsync).
pub const FINE_WINDOW: u32 = 4000;

/// Smaller fine window for constrained first-pass experiments (CLI may override).
pub const FINE_WINDOW_FAST: u32 = 500;

/// Coarse stratified stride (heights sampled every N blocks).
pub const COARSE_STRIDE: u32 = 100;

/// Mainnet MWEB activation height (approx.; used as coarse-map floor).
pub const MAINNET_MWEB_ACTIVATION_HEIGHT: u32 = 2_215_000;

/// Dating strategy for newly scanned UTXOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DatingMode {
    /// Sample last [`MwebSyncer::fine_window`] heights (+ optional coarse stride).
    #[default]
    FineWindow,
    /// Only record tip `output_mmr_size` (fast first sync; heights ≈ tip).
    TipOnly,
}

/// Result of comparing two leafset bitsets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafsetDiff {
    /// Bits that flipped 0 → 1 (new unspent leaves).
    pub added: Vec<u64>,
    /// Bits that flipped 1 → 0 (spent / purged leaves).
    pub removed: Vec<u64>,
}

/// Diff `old` vs `new` leafset blobs (MSB-first bits, same layout as [`MwebLeafset`]).
pub fn diff_leafsets(old: &[u8], new: &[u8]) -> LeafsetDiff {
    let max_len = old.len().max(new.len());
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for byte_i in 0..max_len {
        let o = old.get(byte_i).copied().unwrap_or(0);
        let n = new.get(byte_i).copied().unwrap_or(0);
        let changed = o ^ n;
        if changed == 0 {
            continue;
        }
        for bit in 0..8u64 {
            let mask = 1u8 << (7 - bit);
            if changed & mask == 0 {
                continue;
            }
            let idx = byte_i as u64 * 8 + bit;
            if n & mask != 0 {
                added.push(idx);
            } else {
                removed.push(idx);
            }
        }
    }
    LeafsetDiff { added, removed }
}

/// How often [`MwebSyncer::run_once`] invokes the optional checkpoint callback.
pub const CHECKPOINT_EVERY_BATCHES: usize = 50;

/// Persistent / in-memory sync cursor (leafset snapshot + height→leaf map).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncState {
    /// Last verified tip hash.
    #[cfg_attr(feature = "serde", serde(default))]
    pub tip_hash: Option<BlockHash>,
    /// Last verified tip height.
    #[cfg_attr(feature = "serde", serde(default))]
    pub tip_height: Option<u32>,
    /// Leafset bitset at [`Self::tip_hash`] (empty = first sync downloads all UTXOs).
    #[cfg_attr(feature = "serde", serde(default))]
    pub leafset: Vec<u8>,
    /// Stratified height → `output_mmr_size` (cumulative leaf count).
    #[cfg_attr(feature = "serde", serde(default))]
    pub height_map: BTreeMap<u32, u64>,
    /// Tip hash of an in-progress UTXO download (cleared when a pass finishes).
    #[cfg_attr(feature = "serde", serde(default))]
    pub pending_tip_hash: Option<BlockHash>,
    /// Last leaf index successfully fetched for [`Self::pending_tip_hash`] (inclusive).
    #[cfg_attr(feature = "serde", serde(default))]
    pub utxo_cursor: Option<u64>,
}

impl SyncState {
    /// Empty state (forces full UTXO download on next [`MwebSyncer::run_once`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop leafset snapshot so the next pass re-downloads (reorg / tip hash change).
    pub fn invalidate_leafset(&mut self) {
        self.leafset.clear();
        self.tip_hash = None;
        self.clear_utxo_resume();
        // Keep tip_height / height_map for dating; leafset empty ⇒ full added set.
    }

    /// Clear mid-download resume markers.
    pub fn clear_utxo_resume(&mut self) {
        self.pending_tip_hash = None;
        self.utxo_cursor = None;
    }
}

/// Date a leaf index using a height→`output_mmr_size` map (mwebsync binary-search semantics).
///
/// Returns the first sampled height where `leaves_at_height > leaf_index`, else `tip_height`.
pub fn date_leaf_index(
    height_map: &BTreeMap<u32, u64>,
    leaf_index: u64,
    tip_height: u32,
) -> u32 {
    // heights ascending; first where (leaves - 1) >= leaf_index ⇔ leaves > leaf_index
    for (&height, &leaves) in height_map.iter() {
        if leaves > leaf_index {
            return height;
        }
    }
    tip_height
}

/// Transparent tip seam: tip hash/height and block hash by height (for MWEB header sampling).
pub trait BlockHeaderProvider {
    /// Best known transparent tip.
    fn tip(&self) -> Result<(BlockHash, u32), Error>;
    /// Block hash at `height` (must exist on the caller's chain view).
    fn block_hash_at(&self, height: u32) -> Result<BlockHash, Error>;
}

/// Wait for transparent headers before MWEB sync (CLI usually no-ops after Esplora sync).
pub trait SyncNotifier {
    /// Block until transparent headers are caught up enough to sync MWEB.
    fn wait_headers_synced(&mut self) -> Result<(), Error>;
    /// Current transparent tip height.
    fn header_tip_height(&self) -> Result<u32, Error>;
    /// Block until the transparent tip moves past `prev_height` (tip-loop idle).
    ///
    /// Default: return immediately (one-shot / tests). Product notifiers should sleep/poll.
    fn wait_tip_changed(&mut self, _prev_height: u32) -> Result<(), Error> {
        Ok(())
    }
}

/// Notifier that assumes headers are already synced.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadyNotifier {
    /// Tip height reported by [`SyncNotifier::header_tip_height`].
    pub tip_height: u32,
}

impl SyncNotifier for ReadyNotifier {
    fn wait_headers_synced(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn header_tip_height(&self) -> Result<u32, Error> {
        Ok(self.tip_height)
    }
}

/// Tip notifier that polls a height callback until the tip advances (mobile tip-loop idle).
#[cfg(feature = "std")]
pub struct PollingTipNotifier<F>
where
    F: FnMut() -> Result<u32, Error>,
{
    /// Returns the current transparent tip height.
    pub tip_fn: F,
    /// Sleep between polls.
    pub poll: std::time::Duration,
    /// Last observed tip (updated on each poll).
    pub tip_height: u32,
}

#[cfg(feature = "std")]
impl<F> PollingTipNotifier<F>
where
    F: FnMut() -> Result<u32, Error>,
{
    /// Construct with an initial tip height and poll interval.
    pub fn new(tip_height: u32, poll: std::time::Duration, tip_fn: F) -> Self {
        Self {
            tip_fn,
            poll,
            tip_height,
        }
    }
}

#[cfg(feature = "std")]
impl<F> SyncNotifier for PollingTipNotifier<F>
where
    F: FnMut() -> Result<u32, Error>,
{
    fn wait_headers_synced(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn header_tip_height(&self) -> Result<u32, Error> {
        Ok(self.tip_height)
    }

    fn wait_tip_changed(&mut self, prev_height: u32) -> Result<(), Error> {
        loop {
            let h = (self.tip_fn)()?;
            self.tip_height = h;
            if h > prev_height {
                return Ok(());
            }
            std::thread::sleep(self.poll);
        }
    }
}

/// Fixed tip + optional height→hash map (tests / CLI after Esplora).
#[derive(Debug, Clone)]
pub struct FixedHeaderProvider {
    /// Tip block hash.
    pub tip_hash: BlockHash,
    /// Tip height.
    pub tip_height: u32,
    /// Optional hash lookup for stratified sampling. Missing heights skip sampling.
    pub hashes: BTreeMap<u32, BlockHash>,
}

impl FixedHeaderProvider {
    /// Provider that only knows the tip (fine-window sampling limited to tip header).
    pub fn tip_only(tip_hash: BlockHash, tip_height: u32) -> Self {
        let mut hashes = BTreeMap::new();
        hashes.insert(tip_height, tip_hash);
        Self {
            tip_hash,
            tip_height,
            hashes,
        }
    }

    /// Refresh tip fields (keeps prior fine-window hashes).
    pub fn set_tip(&mut self, tip_hash: BlockHash, tip_height: u32) {
        self.tip_hash = tip_hash;
        self.tip_height = tip_height;
        self.hashes.insert(tip_height, tip_hash);
    }
}

impl BlockHeaderProvider for FixedHeaderProvider {
    fn tip(&self) -> Result<(BlockHash, u32), Error> {
        Ok((self.tip_hash, self.tip_height))
    }

    fn block_hash_at(&self, height: u32) -> Result<BlockHash, Error> {
        self.hashes.get(&height).copied().ok_or_else(|| {
            Error::Crypto(format!("FixedHeaderProvider: no hash for height {height}"))
        })
    }
}

/// Live tip provider: re-queries tip / hashes on each call (not a frozen snapshot).
pub struct LiveHeaderProvider<T, H>
where
    T: Fn() -> Result<(BlockHash, u32), Error>,
    H: Fn(u32) -> Result<BlockHash, Error>,
{
    /// Returns current `(tip_hash, tip_height)`.
    pub tip_fn: T,
    /// Returns block hash at height.
    pub hash_fn: H,
}

impl<T, H> LiveHeaderProvider<T, H>
where
    T: Fn() -> Result<(BlockHash, u32), Error>,
    H: Fn(u32) -> Result<BlockHash, Error>,
{
    /// Construct from tip and per-height hash callbacks.
    pub fn new(tip_fn: T, hash_fn: H) -> Self {
        Self { tip_fn, hash_fn }
    }
}

impl<T, H> BlockHeaderProvider for LiveHeaderProvider<T, H>
where
    T: Fn() -> Result<(BlockHash, u32), Error>,
    H: Fn(u32) -> Result<BlockHash, Error>,
{
    fn tip(&self) -> Result<(BlockHash, u32), Error> {
        (self.tip_fn)()
    }

    fn block_hash_at(&self, height: u32) -> Result<BlockHash, Error> {
        (self.hash_fn)(height)
    }
}

/// Contiguous spans of sorted leaf indices, capped at `max_span`.
#[cfg(test)]
fn index_spans(indices: &[u64], max_span: u16) -> Vec<(u64, u16)> {
    let mut spans = Vec::new();
    if indices.is_empty() {
        return spans;
    }
    let max_span = max_span.max(1) as u64;
    let mut start = indices[0];
    let mut prev = indices[0];
    let mut count = 1u64;
    for &idx in &indices[1..] {
        if idx == prev + 1 && count < max_span {
            prev = idx;
            count += 1;
        } else {
            spans.push((start, count as u16));
            start = idx;
            prev = idx;
            count = 1;
        }
    }
    spans.push((start, count as u16));
    spans
}

/// Drop / trim spans so only leaves strictly after `cursor` remain.
#[cfg(test)]
fn filter_spans_after_cursor(spans: Vec<(u64, u16)>, cursor: Option<u64>) -> Vec<(u64, u16)> {
    let Some(c) = cursor else {
        return spans;
    };
    let mut out = Vec::new();
    for (start, count) in spans {
        let end = start + count as u64 - 1;
        if end <= c {
            continue;
        }
        if start > c {
            out.push((start, count));
        } else {
            let new_start = c + 1;
            let new_count = (end - new_start + 1) as u16;
            out.push((new_start, new_count));
        }
    }
    out
}

/// MSB-first leafset bit test (same layout as [`diff_leafsets`] / [`MwebLeafset`]).
fn leafset_has_leaf(leafset: &[u8], leaf: u64) -> bool {
    let byte_i = (leaf / 8) as usize;
    let bit = (leaf % 8) as u8;
    let mask = 1u8 << (7 - bit);
    leafset.get(byte_i).is_some_and(|b| b & mask != 0)
}

/// Heights to sample for the fine window ending at `tip_height`.
pub fn fine_sample_heights(tip_height: u32, window: u32) -> Vec<u32> {
    if window == 0 {
        return vec![tip_height];
    }
    let start = tip_height.saturating_sub(window.saturating_sub(1));
    (start..=tip_height).collect()
}

/// Coarse sample heights from `from_height` to `tip_height` (inclusive), every `stride` blocks.
pub fn coarse_sample_heights(from_height: u32, tip_height: u32, stride: u32) -> Vec<u32> {
    let stride = stride.max(1);
    let mut out = Vec::new();
    let mut h = from_height;
    while h < tip_height {
        out.push(h);
        h = h.saturating_add(stride);
    }
    if out.last().copied() != Some(tip_height) {
        out.push(tip_height);
    }
    out
}

/// Try each peer address until one connects (multi-peer failover, no ban manager).
#[cfg(feature = "std")]
pub fn connect_first_peer(
    addrs: &[std::net::SocketAddr],
    network: bitcoin::Network,
) -> Result<crate::lip0006_tcp::TcpMwebPeer, Error> {
    PeerPool::new(addrs.to_vec()).connect_next(network)
}

/// Simple multi-peer pool with temporary bans (invalid proof / timeout / connect fail).
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PeerPool {
    addrs: Vec<std::net::SocketAddr>,
    /// Banned until `Instant` (std time).
    banned: BTreeMap<std::net::SocketAddr, std::time::Instant>,
    /// Ban duration for soft failures.
    ban_for: std::time::Duration,
    next: usize,
}

#[cfg(feature = "std")]
impl PeerPool {
    /// Create a pool from peer addresses (order = preference).
    pub fn new(addrs: Vec<std::net::SocketAddr>) -> Self {
        Self {
            addrs,
            banned: BTreeMap::new(),
            ban_for: std::time::Duration::from_secs(300),
            next: 0,
        }
    }

    /// Ban `addr` for the configured duration (e.g. after PMMR / leafset failure).
    pub fn ban(&mut self, addr: std::net::SocketAddr) {
        self.banned
            .insert(addr, std::time::Instant::now() + self.ban_for);
    }

    /// Whether `addr` is currently banned.
    pub fn is_banned(&self, addr: std::net::SocketAddr) -> bool {
        match self.banned.get(&addr) {
            Some(until) => std::time::Instant::now() < *until,
            None => false,
        }
    }

    /// Connect to the next non-banned peer (round-robin).
    pub fn connect_next(
        &mut self,
        network: bitcoin::Network,
    ) -> Result<crate::lip0006_tcp::TcpMwebPeer, Error> {
        if self.addrs.is_empty() {
            return Err(Error::Crypto("no LIP-0006 peer addresses".into()));
        }
        let n = self.addrs.len();
        let mut last_err = None;
        for _ in 0..n {
            let addr = self.addrs[self.next % n];
            self.next = self.next.wrapping_add(1);
            if self.is_banned(addr) {
                continue;
            }
            match crate::lip0006_tcp::TcpMwebPeer::connect(&addr, network) {
                Ok(p) => return Ok(p),
                Err(e) => {
                    self.ban(addr);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Crypto("all peers banned or unreachable".into())))
    }
}

/// mwebsync-shaped syncer over a single [`MwebUtxoSource`].
#[derive(Debug)]
pub struct MwebSyncer {
    /// Verification mode for tip header / leafset / UTXO batches.
    pub verify: VerifyMode,
    /// UTXO batch size for `getmwebutxos`.
    pub batch_size: u16,
    /// Fine stratified window size (ignored when [`DatingMode::TipOnly`]).
    pub fine_window: u32,
    /// UTXO dating strategy.
    pub dating: DatingMode,
    /// When set, also sample coarse heights from this floor to tip (stride [`COARSE_STRIDE`]).
    pub coarse_from_height: Option<u32>,
}

impl Default for MwebSyncer {
    fn default() -> Self {
        Self {
            verify: VerifyMode::HeaderAndPmmr,
            batch_size: DEFAULT_UTXO_BATCH,
            fine_window: FINE_WINDOW,
            dating: DatingMode::FineWindow,
            coarse_from_height: None,
        }
    }
}

impl MwebSyncer {
    /// Construct with defaults ([`VerifyMode::HeaderAndPmmr`], fine window [`FINE_WINDOW`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Fast first-sync preset: tip-only dating (no 500-header storm).
    pub fn tip_only() -> Self {
        Self {
            dating: DatingMode::TipOnly,
            fine_window: 1,
            ..Self::default()
        }
    }

    /// Sample headers into `state.height_map` per [`Self::dating`].
    pub fn sample_fine_headers<P, S>(
        &self,
        headers: &P,
        source: &mut S,
        state: &mut SyncState,
        tip_height: u32,
    ) -> Result<(), Error>
    where
        P: BlockHeaderProvider,
        S: MwebUtxoSource,
    {
        let mut heights = match self.dating {
            DatingMode::TipOnly => vec![tip_height],
            DatingMode::FineWindow => fine_sample_heights(tip_height, self.fine_window),
        };
        if let Some(from) = self.coarse_from_height {
            if matches!(self.dating, DatingMode::FineWindow) {
                for h in coarse_sample_heights(from.min(tip_height), tip_height, COARSE_STRIDE) {
                    if !heights.contains(&h) {
                        heights.push(h);
                    }
                }
                heights.sort_unstable();
                heights.dedup();
            }
        }
        for height in heights {
            if state.height_map.contains_key(&height) {
                continue;
            }
            let Ok(hash) = headers.block_hash_at(height) else {
                continue;
            };
            match source.get_header(hash) {
                Ok(msg) => {
                    state
                        .height_map
                        .insert(height, msg.mweb_header.output_mmr_size);
                }
                Err(_) => continue,
            }
        }
        let (tip_hash, _) = headers.tip()?;
        if let Ok(msg) = source.get_header(tip_hash) {
            state
                .height_map
                .insert(tip_height, msg.mweb_header.output_mmr_size);
        }
        Ok(())
    }

    /// One differential sync pass at the transparent tip.
    ///
    /// When `checkpoint` is set, it is invoked every [`CHECKPOINT_EVERY_BATCHES`] UTXO
    /// batches (and once before returning) so callers can persist [`SyncState`] and the
    /// coin DB mid-download. On failure, [`SyncState::utxo_cursor`] lets the next pass
    /// resume at the same tip.
    pub fn run_once<P, N, S>(
        &self,
        headers: &P,
        notifier: &mut N,
        source: &mut S,
        state: &mut SyncState,
        keys: &MasterKeys,
        book: &AddressBook,
        db: &mut MwebCoinDatabase,
        secp: &Secp256k1<All>,
        mut checkpoint: Option<&mut dyn FnMut(&SyncState, &mut MwebCoinDatabase)>,
    ) -> Result<SyncResult, Error>
    where
        P: BlockHeaderProvider,
        N: SyncNotifier,
        S: MwebUtxoSource,
    {
        notifier.wait_headers_synced()?;
        let (tip_hash, tip_height) = headers.tip()?;

        // Reorg / tip divergence: clear dated heights and force a fresh leafset baseline.
        let tip_changed = state.tip_hash.is_some_and(|h| h != tip_hash);
        let tip_shorter = state
            .tip_height
            .is_some_and(|prev| tip_height + 1 < prev);
        if tip_shorter || tip_changed {
            if tip_shorter {
                db.disconnect_from(tip_height.saturating_add(1));
            } else if tip_changed {
                // Same or higher height but different hash — clear from common ancestor heuristically.
                let rewind = tip_height.saturating_sub(10).saturating_add(1);
                db.disconnect_from(rewind);
            }
            state.invalidate_leafset();
            state.height_map.retain(|&h, _| h < tip_height.saturating_sub(self.fine_window.max(1)));
        }

        self.sample_fine_headers(headers, source, state, tip_height)?;

        let header_msg = if matches!(self.verify, VerifyMode::HeaderAndPmmr) {
            Some(source.get_header(tip_hash)?)
        } else {
            None
        };
        let mweb_header = header_msg.as_ref().map(|h| h.mweb_header.clone());
        if let Some(ref hdr) = mweb_header {
            state
                .height_map
                .insert(tip_height, hdr.output_mmr_size);
        }

        let leafset = source.get_leafset(tip_hash)?;
        if leafset.block_hash != tip_hash {
            return Err(Error::Crypto("leafset block_hash mismatch".into()));
        }
        if let Some(ref hdr) = mweb_header {
            verify_leafset(&leafset, &hdr.leafset_root, hdr.output_mmr_size)?;
        }

        let diff = diff_leafsets(&state.leafset, &leafset.leafset);

        let mut result = SyncResult {
            mweb_header: mweb_header.clone(),
            ..SyncResult::default()
        };

        for leaf in &diff.removed {
            if let Some(id) = db.mark_spent_by_leaf_index(*leaf) {
                result.spent.push(id);
            }
        }

        let added_set: BTreeSet<u64> = diff.added.iter().copied().collect();
        let mut all_fetched_ids = BTreeSet::new();
        // Resume mid-download: same tip, or first-sync (empty leafset) across tip advance.
        // Leaf indices are append-only; a higher tip only adds higher leaves / clears spent bits.
        let resume_cursor = match (state.utxo_cursor, state.pending_tip_hash, state.leafset.is_empty()) {
            (Some(c), Some(pending), true) if pending != tip_hash => {
                #[cfg(feature = "std")]
                eprintln!(
                    "Tip moved during first sync ({pending} → {tip_hash}); resuming after leaf {c}"
                );
                Some(c)
            }
            (Some(c), Some(pending), _) if pending == tip_hash => Some(c),
            (Some(c), None, true) => Some(c), // legacy / partial state
            _ => None,
        };

        // Walk added indices like `sync_mweb_utxos`: each request asks for `batch_size`
        // unspent UTXOs from `start_index`, then skip all added leaves ≤ last returned.
        // (Sparse contiguous spans were ~1 UTXO/request → tens of thousands of round-trips.)
        let indices = &diff.added;
        let mut idx_i = 0usize;
        if let Some(c) = resume_cursor {
            while idx_i < indices.len() && indices[idx_i] <= c {
                idx_i += 1;
            }
        }
        let remaining = indices.len().saturating_sub(idx_i);
        let batch_size = self.batch_size.max(1) as usize;
        let approx_batches = remaining.div_ceil(batch_size).max(1);
        #[cfg(feature = "std")]
        {
            if let Some(c) = resume_cursor {
                eprintln!(
                    "Resuming UTXO download after leaf {c} (~{approx_batches} batches left, remaining_added={remaining})"
                );
            } else {
                eprintln!(
                    "Downloading {remaining} added UTXOs in ~{approx_batches} batches (batch_size={batch_size})"
                );
            }
        }

        state.pending_tip_hash = Some(tip_hash);
        let height_map = state.height_map.clone();
        let mut batch_i = 0usize;
        // Prefer large requests; some wide PMMR segments fail verify — then halve.
        let mut req_size = self.batch_size.max(1);

        while idx_i < indices.len() {
            batch_i += 1;
            let start = indices[idx_i];
            #[cfg(feature = "std")]
            if batch_i == 1 || batch_i % 10 == 0 || idx_i + batch_size >= indices.len() {
                eprintln!(
                    "  utxo batch {batch_i}/~{approx_batches} (start_leaf={start}, remaining={}, req={req_size}, added={})",
                    indices.len() - idx_i,
                    diff.added.len()
                );
            }

            let batch = loop {
                let req = GetMwebUtxos {
                    block_hash: tip_hash,
                    start_index: start,
                    num_requested: req_size,
                    output_format: OUTPUT_FORMAT_FULL,
                };
                let batch = source.get_utxos(req)?;
                if batch.output_format != OUTPUT_FORMAT_FULL {
                    return Err(Error::Crypto("expected FULL_UTXO format".into()));
                }
                let verify_res = match self.verify {
                    VerifyMode::Trusted => verify_parent_hashes_present(&batch),
                    VerifyMode::HeaderAndPmmr => {
                        let hdr = mweb_header.as_ref().expect("header fetched");
                        verify_utxo_batch(&batch, &leafset, hdr)
                    }
                };
                match verify_res {
                    Ok(()) => break batch,
                    Err(e) => {
                        let msg = alloc::format!("{e}");
                        let can_shrink = req_size > 1
                            && (msg.contains("output_root mismatch")
                                || msg.contains("parent_hashes len")
                                || msg.contains("missing peak"));
                        if !can_shrink {
                            return Err(e);
                        }
                        let next = (req_size / 2).max(1);
                        #[cfg(feature = "std")]
                        eprintln!(
                            "warn: PMMR verify failed at leaf {start} with req={req_size} ({msg}); retrying with {next}"
                        );
                        req_size = next;
                    }
                }
            };

            if batch.utxos.is_empty() {
                // Nothing at/after this leaf; skip it so we cannot spin forever.
                idx_i += 1;
                continue;
            }
            let mut entries: Vec<(u64, Output)> = Vec::new();
            for entry in &batch.utxos {
                if !added_set.contains(&entry.leaf_index) {
                    continue;
                }
                let oid = crate::scan::output_id(&entry.output);
                all_fetched_ids.insert(oid);
                entries.push((entry.leaf_index, entry.output.clone()));
            }
            let last_leaf = batch
                .utxos
                .last()
                .map(|e| e.leaf_index)
                .unwrap_or(start);

            let found = scan_utxo_entries_at(keys, book, &entries, db, secp, |leaf| {
                Some(date_leaf_index(&height_map, leaf, tip_height))
            })?;
            result.found.extend(found);
            result.downloaded = result.downloaded.saturating_add(batch.utxos.len());

            while idx_i < indices.len() && indices[idx_i] <= last_leaf {
                idx_i += 1;
            }
            state.utxo_cursor = Some(last_leaf);

            // After a successful verify, gradually restore larger batches.
            if req_size < self.batch_size {
                req_size = (req_size.saturating_mul(2)).min(self.batch_size).max(1);
            }

            let done = idx_i >= indices.len();
            let should_checkpoint = checkpoint.is_some()
                && (batch_i == 1
                    || batch_i % CHECKPOINT_EVERY_BATCHES == 0
                    || done);
            if should_checkpoint {
                if let Some(cb) = checkpoint.as_mut() {
                    cb(state, db);
                }
            }
        }

        // Re-date existing coins that already carry a leaf_index (e.g. after fine map grows).
        let to_update: Vec<([u8; 32], u32)> = db
            .unspent()
            .filter_map(|c| {
                let leaf = c.leaf_index?;
                let h = date_leaf_index(&height_map, leaf, tip_height);
                if c.block_height != Some(h) {
                    Some((c.output_id, h))
                } else {
                    None
                }
            })
            .collect();
        for (id, h) in to_update {
            db.set_block_height(&id, h);
        }

        // First sync (empty prior leafset): mark local coins absent from the unspent
        // leafset as spent. Prefer leaf_index bits so mid-sync resume stays correct.
        if state.leafset.is_empty() {
            let local: Vec<([u8; 32], Option<u64>)> =
                db.unspent().map(|c| (c.output_id, c.leaf_index)).collect();
            for (id, leaf) in local {
                let gone = match leaf {
                    Some(i) => !leafset_has_leaf(&leafset.leafset, i),
                    None => !all_fetched_ids.contains(&id) && resume_cursor.is_none(),
                };
                if gone && db.mark_spent(&id) {
                    if !result.spent.contains(&id) {
                        result.spent.push(id);
                    }
                }
            }
        }

        state.tip_hash = Some(tip_hash);
        state.tip_height = Some(tip_height);
        state.leafset = leafset.leafset;
        state.clear_utxo_resume();

        if let Some(cb) = checkpoint.as_mut() {
            cb(state, db);
        }

        Ok(result)
    }

    /// Call [`Self::run_once`] until `should_stop` returns true (checked after each pass).
    ///
    /// Between passes, waits via [`SyncNotifier::wait_tip_changed`] so idle tip loops do not
    /// busy-spin. For mid-pass persistence, callers should use [`Self::run_once`] with a
    /// checkpoint closure (as the CLI does).
    pub fn run_loop<P, N, S, F>(
        &self,
        headers: &P,
        notifier: &mut N,
        source: &mut S,
        state: &mut SyncState,
        keys: &MasterKeys,
        book: &AddressBook,
        db: &mut MwebCoinDatabase,
        secp: &Secp256k1<All>,
        mut should_stop: F,
    ) -> Result<SyncResult, Error>
    where
        P: BlockHeaderProvider,
        N: SyncNotifier,
        S: MwebUtxoSource,
        F: FnMut() -> bool,
    {
        let mut last;
        loop {
            let tip_before = notifier.header_tip_height().unwrap_or(0);
            last = self.run_once(
                headers,
                notifier,
                source,
                state,
                keys,
                book,
                db,
                secp,
                None,
            )?;
            if should_stop() {
                break;
            }
            notifier.wait_tip_changed(tip_before)?;
        }
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coin_db::MwebCoin;
    use crate::p2p::MwebLeafset;
    use bitcoin::hashes::Hash;

    #[cfg(feature = "std")]
    #[test]
    fn peer_pool_bans_failed_connect() {
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut pool = PeerPool::new(vec![addr]);
        let _ = pool.connect_next(bitcoin::Network::Regtest);
        assert!(pool.is_banned(addr));
    }

    #[test]
    fn fine_window_matches_mwebsync_default() {
        assert_eq!(FINE_WINDOW, 4000);
        assert_eq!(FINE_WINDOW_FAST, 500);
    }

    #[test]
    fn live_header_provider_refreshes_tip() {
        use core::cell::Cell;
        let height = Cell::new(10u32);
        let hash_a = BlockHash::from_byte_array([1u8; 32]);
        let hash_b = BlockHash::from_byte_array([2u8; 32]);
        let provider = LiveHeaderProvider::new(
            || {
                let h = height.get();
                let hash = if h > 10 { hash_b } else { hash_a };
                Ok((hash, h))
            },
            |h| Ok(BlockHash::from_byte_array([h as u8; 32])),
        );
        assert_eq!(provider.tip().unwrap(), (hash_a, 10));
        height.set(11);
        assert_eq!(provider.tip().unwrap(), (hash_b, 11));
        assert_eq!(
            provider.block_hash_at(11).unwrap(),
            BlockHash::from_byte_array([11u8; 32])
        );
    }

    #[test]
    fn diff_detects_added_and_removed() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let old = MwebLeafset::from_indices(hash, &[0, 2, 5]).leafset;
        let new = MwebLeafset::from_indices(hash, &[0, 3, 5]).leafset;
        let d = diff_leafsets(&old, &new);
        assert_eq!(d.added, vec![3]);
        assert_eq!(d.removed, vec![2]);
    }

    #[test]
    fn diff_empty_old_adds_all() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let new = MwebLeafset::from_indices(hash, &[1, 4, 7]).leafset;
        let d = diff_leafsets(&[], &new);
        assert_eq!(d.added, vec![1, 4, 7]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn date_leaf_binary_search_semantics() {
        let mut map = BTreeMap::new();
        map.insert(100, 10); // leaves 0..9 exist by height 100
        map.insert(200, 50);
        map.insert(300, 100);
        assert_eq!(date_leaf_index(&map, 0, 300), 100);
        assert_eq!(date_leaf_index(&map, 9, 300), 100);
        assert_eq!(date_leaf_index(&map, 10, 300), 200);
        assert_eq!(date_leaf_index(&map, 49, 300), 200);
        assert_eq!(date_leaf_index(&map, 50, 300), 300);
        assert_eq!(date_leaf_index(&map, 99, 300), 300);
        assert_eq!(date_leaf_index(&map, 100, 300), 300); // tip fallback
    }

    #[test]
    fn fine_sample_heights_window() {
        assert_eq!(fine_sample_heights(10, 5), vec![6, 7, 8, 9, 10]);
        assert_eq!(fine_sample_heights(3, 10), vec![0, 1, 2, 3]);
        assert_eq!(fine_sample_heights(10, 0), vec![10]);
    }

    #[test]
    fn coarse_sample_stride() {
        assert_eq!(
            coarse_sample_heights(100, 350, 100),
            vec![100, 200, 300, 350]
        );
    }

    #[test]
    fn index_spans_groups_contiguous() {
        let spans = index_spans(&[1, 2, 3, 10, 11], 100);
        assert_eq!(spans, vec![(1, 3), (10, 2)]);
        let capped = index_spans(&[0, 1, 2, 3], 2);
        assert_eq!(capped, vec![(0, 2), (2, 2)]);
    }

    #[test]
    fn mark_spent_by_leaf_index_roundtrip() {
        let mut db = MwebCoinDatabase::new();
        db.insert(MwebCoin {
            output_id: [9; 32],
            commitment: [0; 33],
            amount: 1,
            address_index: 0,
            blind: [0; 32],
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
            block_height: Some(1),
            is_pegin: false,
            leaf_index: Some(42),
        });
        assert_eq!(db.mark_spent_by_leaf_index(42), Some([9; 32]));
        assert!(db.is_spent(&[9; 32]));
    }

    #[test]
    fn filter_spans_after_cursor_trims() {
        let spans = vec![(0, 10), (20, 5), (30, 3)];
        assert_eq!(
            filter_spans_after_cursor(spans.clone(), None),
            spans
        );
        assert_eq!(
            filter_spans_after_cursor(spans.clone(), Some(9)),
            vec![(20, 5), (30, 3)]
        );
        assert_eq!(
            filter_spans_after_cursor(spans.clone(), Some(22)),
            vec![(23, 2), (30, 3)]
        );
        assert!(filter_spans_after_cursor(spans, Some(100)).is_empty());
    }

    #[test]
    fn leafset_has_leaf_msb() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let ls = MwebLeafset::from_indices(hash, &[0, 3, 8]).leafset;
        assert!(leafset_has_leaf(&ls, 0));
        assert!(!leafset_has_leaf(&ls, 1));
        assert!(leafset_has_leaf(&ls, 3));
        assert!(leafset_has_leaf(&ls, 8));
    }
}
