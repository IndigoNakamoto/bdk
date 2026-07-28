//! Litecoin regtest smoke test for [`bdk_bitcoind_rpc::Emitter`].
//!
//! Requires `LITECOIND_EXE` (skips when unset).

use std::collections::BTreeSet;

use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_chain::local_chain::LocalChain;
use bdk_testenv::try_node_from_env;
use bitcoincore_rpc::{Auth, Client, RpcApi};

#[test]
fn emitter_syncs_local_chain_on_litecoin_regtest() {
    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let client =
        Client::new(&env.rpc_url, Auth::CookieFile(env.cookie_file.clone())).expect("rpc client");

    let genesis = client.get_block_hash(0).expect("genesis");
    let (mut local_chain, _) = LocalChain::from_genesis(genesis);
    let mut emitter = Emitter::new(&client, local_chain.tip(), 0, NO_EXPECTED_MEMPOOL_TXS);

    let mining = env.rpc.get_new_address().expect("mining addr");
    env.rpc.generate_to_address(10, &mining).expect("mine");

    let mut emitted = BTreeSet::new();
    while let Some(emission) = emitter.next_block().expect("next_block") {
        let height = emission.block_height();
        let hash = emission.block_hash();
        local_chain
            .apply_update(emission.checkpoint)
            .expect("apply_update");
        emitted.insert((height, hash));
    }

    let tip = client.get_block_count().expect("tip") as u32;
    assert!(tip >= 10, "expected at least 10 blocks mined, tip={tip}");
    assert!(
        emitted.iter().any(|(h, _)| *h == tip),
        "emitter must reach tip {tip}; emitted={emitted:?}"
    );
    assert_eq!(local_chain.tip().height(), tip);
}
