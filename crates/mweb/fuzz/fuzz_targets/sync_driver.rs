//! F-Z10: liveness of the sync loop against a hostile peer.
//!
//! `sync_mweb_utxos` advances its leaf cursor from the batches the peer returns. A
//! peer that answers with leaves *below* the requested start leaves the cursor
//! where it was, so the same request repeats forever while the accumulated output
//! buffer grows. The batch is well-formed and its leaves really are in the tree, so
//! PMMR verification does not catch it.
//!
//! A hang is a poor fuzzing signal — honggfuzz can only report it as a timeout, and
//! only after burning the whole budget. The source here counts its calls and panics
//! past a bound that no honest sync would reach, converting the hang into an
//! immediate, minimizable crash.

use bdk_mweb::coin_db::MwebCoinDatabase;
use bdk_mweb::error::Error;
use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::{sync_mweb_utxos, MwebUtxoSource, VerifyMode};
use bdk_mweb::p2p::{
    GetMwebUtxos, MwebHeaderMsg, MwebLeafset, MwebUtxoEntry, MwebUtxos, OUTPUT_FORMAT_FULL,
};
use bdk_mweb::scan::AddressBook;
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;
use litecoin::blockdata::mimblewimble::{Output, OutputMessage};
use litecoin::hashes::Hash;
use litecoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use litecoin::BlockHash;

/// No honest sync issues anywhere near this many requests for a leafset this small.
/// Exceeding it means the cursor stopped advancing.
const CALL_BUDGET: usize = 4096;

struct HostileSource<'a> {
    cur: Cursor<'a>,
    header: MwebHeaderMsg,
    leafset: MwebLeafset,
    pk: PublicKey,
    calls: usize,
}

impl HostileSource<'_> {
    fn output(&mut self) -> Output {
        let mut commitment = [0u8; 33];
        commitment[..32].copy_from_slice(&self.cur.arr32());
        Output {
            commitment,
            sender_public_key: self.pk,
            receiver_public_key: self.pk,
            message: OutputMessage {
                features: 0,
                standard_fields: None,
                extra_data: Vec::new(),
            },
            range_proof: [0u8; 675],
            signature: [0u8; 64],
        }
    }
}

impl MwebUtxoSource for HostileSource<'_> {
    fn get_header(&mut self, _block_hash: BlockHash) -> Result<MwebHeaderMsg, Error> {
        Ok(self.header.clone())
    }

    fn get_leafset(&mut self, _block_hash: BlockHash) -> Result<MwebLeafset, Error> {
        Ok(self.leafset.clone())
    }

    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error> {
        self.calls += 1;
        assert!(
            self.calls <= CALL_BUDGET,
            "sync issued {} requests without terminating: the leaf cursor is not advancing",
            self.calls
        );

        // Answer with leaves the fuzzer picks, deliberately including ones below
        // `req.start_index`. Sync must reject that rather than loop on it.
        let count = (self.cur.u8() % 4) as usize;
        let mut utxos = Vec::with_capacity(count);
        for _ in 0..count {
            let leaf_index = if self.cur.u8() % 2 == 0 {
                req.start_index.saturating_sub(self.cur.u8() as u64)
            } else {
                req.start_index.saturating_add(self.cur.u8() as u64)
            };
            let output = self.output();
            utxos.push(MwebUtxoEntry { leaf_index, output });
        }

        Ok(MwebUtxos {
            block_hash: req.block_hash,
            start_index: req.start_index,
            output_format: OUTPUT_FORMAT_FULL,
            utxos,
            parent_hashes: vec![[0u8; 32]],
        })
    }
}

fn do_test(data: &[u8]) {
    let mut seed = Cursor::new(data);
    let block_hash = BlockHash::from_byte_array([3u8; 32]);

    // A handful of unspent leaves: enough to make the loop iterate, small enough
    // that an honest peer would finish in a few requests.
    let leafset = MwebLeafset::from_indices(block_hash, &[0, 1, 5, 9, 40]);
    let header = MwebHeaderMsg {
        merkle: litecoin::MerkleBlock::from_block_with_predicate(
            &litecoin::blockdata::constants::genesis_block(litecoin::Network::Regtest),
            |_| false,
        ),
        hogex: litecoin::blockdata::constants::genesis_block(litecoin::Network::Regtest).txdata[0]
            .clone(),
        mweb_header: litecoin::blockdata::block::MwebBlockHeader {
            height: 1,
            output_root: seed.arr32(),
            kernel_root: [0u8; 32],
            leafset_root: [0u8; 32],
            kernel_offset: [0u8; 32],
            stealth_offset: [0u8; 32],
            output_mmr_size: 41,
            kernel_mmr_size: 0,
        },
    };

    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);

    let mut source = HostileSource {
        cur: seed,
        header,
        leafset: leafset.clone(),
        pk,
        calls: 0,
    };

    // A wallet that owns nothing: scanning finds no coins, so every batch is
    // downloaded and discarded and only the cursor logic governs termination.
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[7u8; 32],
        litecoin::Network::Regtest,
        MasterKeyScheme::Mwebd,
        &secp,
    )
    .expect("fixed seed derives");
    let book = AddressBook::from_keys(&keys, 1, &secp).expect("fixed seed derives");
    let mut db = MwebCoinDatabase::new();

    // `Trusted` skips PMMR verification, so nothing but the cursor logic itself
    // stops the loop. That is exactly the configuration this target needs.
    let _ = sync_mweb_utxos(
        &mut source,
        &keys,
        &book,
        &mut db,
        &secp,
        block_hash,
        None,
        8,
        VerifyMode::Trusted,
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
