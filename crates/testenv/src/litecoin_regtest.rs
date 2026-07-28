//! Litecoin regtest harness driven by locally provided binaries.
//!
//! Set `LITECOIND_EXE` and `ELECTRS_LTC_EXE` to absolute paths. When either is missing,
//! [`try_from_env`] returns `Ok(None)` so callers can skip cleanly.
//!
//! This avoids forking `bitcoincore-rpc` / `electrsd`. Esplora is not started here: there is no
//! packaged regtest Esplora for Litecoin, so Esplora coverage stays on live testnet.

#![allow(clippy::print_stderr)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bdk_chain::bitcoin::blockdata::mimblewimble;
use bdk_chain::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bdk_chain::bitcoin::{Address, Amount, Block, BlockHash, Network, Transaction, Txid};
use bdk_chain::mweb_pegin_script_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};

/// Unspent output returned by `listunspent`.
#[derive(Debug, Clone)]
pub struct Unspent {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
    pub script_pubkey_hex: String,
}

/// JSON-RPC client for a local `litecoind`.
pub struct RpcClient {
    url: String,
    user: String,
    pass: String,
    agent: ureq::Agent,
}

impl RpcClient {
    pub fn new(url: impl Into<String>, user: impl Into<String>, pass: impl Into<String>) -> Self {
        // Litecoin Core returns HTTP 500 with a JSON-RPC error body for many failures.
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .new_agent();
        Self {
            url: url.into(),
            user: user.into(),
            pass: pass.into(),
            agent,
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "bdk_testenv",
            "method": method,
            "params": params,
        });
        let response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", basic_auth(&self.user, &self.pass))
            .send(&body.to_string())
            .with_context(|| format!("RPC {method} transport failed"))?;

        let text = response
            .into_body()
            .read_to_string()
            .with_context(|| format!("RPC {method} body read failed"))?;
        let parsed: RpcResponse = serde_json::from_str(&text)
            .with_context(|| format!("RPC {method} returned non-JSON: {text}"))?;
        if let Some(err) = parsed.error {
            if !err.is_null() {
                bail!("RPC {method} error: {err}");
            }
        }
        // Void RPCs (e.g. invalidateblock) return `"result": null`.
        Ok(parsed.result.unwrap_or(Value::Null))
    }

    pub fn get_blockchain_info(&self) -> Result<Value> {
        self.call("getblockchaininfo", json!([]))
    }

    pub fn create_wallet(&self, name: &str) -> Result<()> {
        match self.call("createwallet", json!([name])) {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") || msg.contains("Database already exists") {
                    let _ = self.call("loadwallet", json!([name]));
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn get_new_address(&self) -> Result<Address> {
        let v = self.call("getnewaddress", json!([]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("getnewaddress returned non-string"))?;
        Ok(Address::from_str(s)?.require_network(Network::Regtest)?)
    }

    /// `getnewaddress "" "mweb"` — stealth address for peg-in / MWEB receive.
    pub fn get_new_mweb_address(&self) -> Result<Address> {
        let v = self.call("getnewaddress", json!(["", "mweb"]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("getnewaddress(mweb) returned non-string"))?;
        Ok(Address::from_str(s)?.require_network(Network::Regtest)?)
    }

    /// Wallet `gettransaction` hex (works for wallet txs not yet in the txindex path).
    pub fn get_wallet_transaction_hex(&self, txid: &Txid) -> Result<String> {
        let v = self.call("gettransaction", json!([txid.to_string()]))?;
        v["hex"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("gettransaction missing hex"))
    }

    pub fn get_balances_mine_trusted(&self) -> Result<Amount> {
        let v = self.call("getbalances", json!([]))?;
        let btc = v["mine"]["trusted"]
            .as_f64()
            .ok_or_else(|| anyhow!("getbalances.mine.trusted missing"))?;
        Ok(Amount::from_btc(btc)?)
    }

    /// Amount received at an MWEB address (`listreceivedbyaddress`, minconf).
    pub fn list_received_by_mweb_address(&self, address: &Address, minconf: u32) -> Result<Amount> {
        let v = self.call(
            "listreceivedbyaddress",
            json!([minconf, false, true, address.to_string()]),
        )?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("listreceivedbyaddress returned non-array"))?;
        if arr.is_empty() {
            return Ok(Amount::ZERO);
        }
        let btc = arr[0]["amount"]
            .as_f64()
            .ok_or_else(|| anyhow!("listreceivedbyaddress missing amount"))?;
        Ok(Amount::from_btc(btc)?)
    }

    pub fn generate_to_address(&self, n: u32, address: &Address) -> Result<Vec<BlockHash>> {
        let v = self.call("generatetoaddress", json!([n, address.to_string()]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("generatetoaddress returned non-array"))?;
        arr.iter()
            .map(|h| {
                let s = h
                    .as_str()
                    .ok_or_else(|| anyhow!("block hash not a string"))?;
                Ok(s.parse()?)
            })
            .collect()
    }

    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let amount_str = format!("{:.8}", amount.to_btc());
        let v = self.call("sendtoaddress", json!([address.to_string(), amount_str]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("sendtoaddress returned non-string"))?;
        Ok(s.parse()?)
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid> {
        let hex = serialize_hex(tx);
        // maxfeerate=0 disables the absurd-fee check (MWEB weight makes sat/vB noisy).
        let v = self.call("sendrawtransaction", json!([hex, 0.0]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("sendrawtransaction returned non-string"))?;
        Ok(s.parse()?)
    }

    /// `testmempoolaccept` — returns `(allowed, reject-reason)`.
    ///
    /// Passes `maxfeerate=0` so MWEB weight/fee-rate edge cases do not trip the
    /// default absurbly-low-vsize max-fee check during acceptance tests.
    pub fn test_mempool_accept(&self, tx: &Transaction) -> Result<(bool, Option<String>)> {
        let hex = serialize_hex(tx);
        let v = self.call("testmempoolaccept", json!([[hex], 0.0]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("testmempoolaccept returned non-array"))?;
        let first = arr
            .first()
            .ok_or_else(|| anyhow!("testmempoolaccept empty result"))?;
        let allowed = first["allowed"].as_bool().unwrap_or(false);
        let reason = first
            .get("reject-reason")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string());
        Ok((allowed, reason))
    }

    pub fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction> {
        let hex = self.get_raw_transaction_hex(txid)?;
        Ok(deserialize_hex(&hex)?)
    }

    pub fn get_raw_transaction_hex(&self, txid: &Txid) -> Result<String> {
        let v = self.call("getrawtransaction", json!([txid.to_string(), false]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("getrawtransaction returned non-string"))
    }

    pub fn get_block_hash(&self, height: u32) -> Result<BlockHash> {
        let v = self.call("getblockhash", json!([height]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("getblockhash returned non-string"))?;
        Ok(s.parse()?)
    }

    pub fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        let v = self.call("getblock", json!([hash.to_string(), 0]))?;
        let hex = v
            .as_str()
            .ok_or_else(|| anyhow!("getblock returned non-hex"))?;
        Ok(deserialize_hex(hex)?)
    }

    pub fn get_raw_mempool(&self) -> Result<Vec<Txid>> {
        let v = self.call("getrawmempool", json!([]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("getrawmempool returned non-array"))?;
        arr.iter()
            .map(|t| {
                let s = t
                    .as_str()
                    .ok_or_else(|| anyhow!("mempool txid not a string"))?;
                Ok(s.parse()?)
            })
            .collect()
    }

    pub fn list_unspent(&self) -> Result<Vec<Unspent>> {
        let v = self.call("listunspent", json!([]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("listunspent returned non-array"))?;
        arr.iter()
            .map(|u| {
                let txid = u["txid"]
                    .as_str()
                    .ok_or_else(|| anyhow!("listunspent missing txid"))?
                    .parse()?;
                let vout = u["vout"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("listunspent missing vout"))?
                    as u32;
                let amount = Amount::from_btc(
                    u["amount"]
                        .as_f64()
                        .ok_or_else(|| anyhow!("listunspent missing amount"))?,
                )?;
                let script_pubkey_hex = u["scriptPubKey"].as_str().unwrap_or("").to_string();
                Ok(Unspent {
                    txid,
                    vout,
                    amount,
                    script_pubkey_hex,
                })
            })
            .collect()
    }

    /// Build and wallet-sign a raw transaction with one or more inputs and a single output.
    ///
    /// Inputs use BIP125 opt-in RBF (`sequence = 0xfffffffd`) so a higher-fee conflict can replace
    /// an earlier broadcast of the same UTXO.
    pub fn create_and_sign_tx(
        &self,
        inputs: &[(Txid, u32)],
        address: &Address,
        amount: Amount,
    ) -> Result<Transaction> {
        let vin: Vec<Value> = inputs
            .iter()
            .map(|(txid, vout)| {
                json!({
                    "txid": txid.to_string(),
                    "vout": vout,
                    "sequence": 0xfffffffd_u32,
                })
            })
            .collect();
        // Pass amounts as fixed 8-decimal strings. JSON f64 (e.g. `amount.to_btc()`) can round
        // enough to collapse the RBF fee delta Litecoin Core requires.
        let amount_str = format!("{:.8}", amount.to_btc());
        let vout = json!({ address.to_string(): amount_str });
        let hex = self
            .call("createrawtransaction", json!([vin, vout]))?
            .as_str()
            .ok_or_else(|| anyhow!("createrawtransaction returned non-string"))?
            .to_string();
        let signed = self.call("signrawtransactionwithwallet", json!([hex]))?;
        let complete = signed["complete"].as_bool().unwrap_or(false);
        if !complete {
            bail!("signrawtransactionwithwallet incomplete: {signed}");
        }
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| anyhow!("signed tx missing hex"))?;
        Ok(deserialize_hex(signed_hex)?)
    }

    /// Fund + sign a transparent v9 peg-in skeleton and attach a pre-authored `mw_tx`.
    pub fn fund_sign_attach_pegin(
        &self,
        kernel_id: [u8; 32],
        pegin_amount: Amount,
        mw_tx: mimblewimble::Transaction,
    ) -> Result<Transaction> {
        use bdk_chain::bitcoin::absolute::LockTime;
        use bdk_chain::bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
        use bdk_chain::bitcoin::Witness;

        let fee = Amount::from_sat(10_000);
        let unspent = self.list_unspent()?;
        let utxo = unspent
            .iter()
            .find(|u| u.amount > pegin_amount + fee)
            .ok_or_else(|| anyhow!("no UTXO large enough for peg-in + fee"))?;
        let change_addr = self.get_new_address()?;
        let change = utxo.amount - pegin_amount - fee;
        let pegin_spk = mweb_pegin_script_pubkey(&kernel_id);

        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: pegin_amount,
                    script_pubkey: pegin_spk,
                },
                TxOut {
                    value: change,
                    script_pubkey: change_addr.script_pubkey(),
                },
            ],
            mw_tx: None,
            is_hog_ex: false,
        };
        let hex = serialize_hex(&unsigned);
        let signed = self.call("signrawtransactionwithwallet", json!([hex]))?;
        if !signed["complete"].as_bool().unwrap_or(false) {
            bail!("signrawtransactionwithwallet incomplete: {signed}");
        }
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| anyhow!("signed tx missing hex"))?;
        let mut tx: Transaction = deserialize_hex(signed_hex)?;
        tx.mw_tx = Some(mw_tx);
        self.send_raw_transaction(&tx)?;
        Ok(tx)
    }

    pub fn invalidate_block(&self, hash: &BlockHash) -> Result<()> {
        self.call("invalidateblock", json!([hash.to_string()]))?;
        Ok(())
    }

    pub fn get_block_count(&self) -> Result<u32> {
        let v = self.call("getblockcount", json!([]))?;
        Ok(v.as_u64().ok_or_else(|| anyhow!("bad getblockcount"))? as u32)
    }

    pub fn get_best_block_hash(&self) -> Result<BlockHash> {
        let v = self.call("getbestblockhash", json!([]))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("getbestblockhash returned non-string"))?;
        Ok(s.parse()?)
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {token}")
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let socket: std::net::SocketAddr = addr.parse()?;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("timed out waiting for {addr}")
}

fn electrum_call(electrum_host: &str, method: &str, params: Value) -> Result<Value> {
    let mut stream = TcpStream::connect(electrum_host)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let req = json!({ "id": 1, "method": method, "params": params });
    stream.write_all(format!("{req}\n").as_bytes())?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&b'\n') {
            break;
        }
    }
    let line = std::str::from_utf8(&buf)?.lines().next().unwrap_or("");
    let parsed: Value = serde_json::from_str(line)?;
    if let Some(err) = parsed.get("error").filter(|e| !e.is_null()) {
        bail!("electrum {method} error: {err}");
    }
    parsed
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("electrum {method} missing result"))
}

/// Default regtest height of the first block that may contain MWEB (CSV / Core
/// `FIRST_MWEB_HEIGHT`).
pub const FIRST_MWEB_HEIGHT: u32 = 432;

/// Peg-in maturity used by Litecoin Core before MWEB spends are considered safe.
pub const MWEB_PEGIN_MATURITY: u32 = 6;

/// Running `litecoind -regtest` only (no electrs). Enough for MWEB peg-in acceptance tests.
pub struct LitecoinNodeEnv {
    pub datadir: PathBuf,
    /// Path to litecoind cookie auth file (`regtest/.cookie`).
    pub cookie_file: PathBuf,
    pub rpc: RpcClient,
    pub rpc_url: String,
    /// P2P listen port (`-port=`).
    pub p2p_port: u16,
    litecoind: Child,
}

impl LitecoinNodeEnv {
    pub fn from_env() -> Result<Self> {
        let litecoind = std::env::var("LITECOIND_EXE")
            .map_err(|_| anyhow!("LITECOIND_EXE is not set; skipping Litecoin node harness"))?;
        Self::spawn(PathBuf::from(litecoind))
    }

    pub fn spawn(litecoind_exe: PathBuf) -> Result<Self> {
        let (datadir, cookie_file, rpc, rpc_url, p2p_port, litecoind) =
            spawn_litecoind(litecoind_exe)?;
        Ok(Self {
            datadir,
            cookie_file,
            rpc,
            rpc_url,
            p2p_port,
            litecoind,
        })
    }

    /// `127.0.0.1:{p2p_port}` for `bdk_mweb::lip0006_tcp::TcpMwebPeer`.
    pub fn p2p_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self.p2p_port))
    }

    /// Mine to height 431, matching Core's `setup_mweb_chain` pre-activation tip.
    pub fn mine_to_pre_mweb(&self) -> Result<Address> {
        let addr = self.rpc.get_new_address()?;
        let height = self.rpc.get_block_count()?;
        if height < FIRST_MWEB_HEIGHT - 1 {
            self.rpc
                .generate_to_address(FIRST_MWEB_HEIGHT - 1 - height, &addr)?;
        }
        Ok(addr)
    }

    /// Activate MWEB (mine through height 432) after a peg-in is in the mempool, or alone.
    pub fn mine_mweb_activation(&self, mining_addr: &Address) -> Result<()> {
        let height = self.rpc.get_block_count()?;
        if height < FIRST_MWEB_HEIGHT {
            self.rpc
                .generate_to_address(FIRST_MWEB_HEIGHT - height, mining_addr)?;
        }
        Ok(())
    }

    /// Core-wallet finalize: `sendtoaddress` to an MWEB stealth address, return the full tx.
    pub fn finalize_mweb_pegin(
        &self,
        mweb_address: &Address,
        amount: Amount,
    ) -> Result<Transaction> {
        let txid = self.rpc.send_to_address(mweb_address, amount)?;
        let hex = self.rpc.get_wallet_transaction_hex(&txid)?;
        Ok(deserialize_hex(&hex)?)
    }

    /// Broadcast a BDK-authored peg-in: fund/sign transparent v9 half, attach `mw_tx`.
    ///
    /// Does **not** use Core `sendtoaddress` for the MWEB body — `mw_tx` must already be
    /// authored (e.g. `bdk_mweb::build_pegin`).
    pub fn broadcast_bdk_pegin(
        &self,
        kernel_id: [u8; 32],
        pegin_amount: Amount,
        mw_tx: mimblewimble::Transaction,
    ) -> Result<Transaction> {
        self.rpc
            .fund_sign_attach_pegin(kernel_id, pegin_amount, mw_tx)
    }

    pub fn mine_blocks(&self, n: u32, address: &Address) -> Result<Vec<BlockHash>> {
        self.rpc.generate_to_address(n, address)
    }
}

impl Drop for LitecoinNodeEnv {
    fn drop(&mut self) {
        let _ = self.litecoind.kill();
        let _ = self.litecoind.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

/// Return `Ok(None)` when `LITECOIND_EXE` is unset.
pub fn try_node_from_env() -> Result<Option<LitecoinNodeEnv>> {
    match LitecoinNodeEnv::from_env() {
        Ok(env) => Ok(Some(env)),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("is not set") {
                eprintln!("skip: {msg}");
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Running `litecoind -regtest` plus `electrs-ltc` pointed at it.
pub struct LitecoinTestEnv {
    pub datadir: PathBuf,
    pub rpc: RpcClient,
    pub electrum_url: String,
    pub rpc_url: String,
    electrum_host: String,
    litecoind: Child,
    electrs: Child,
}

fn spawn_litecoind(
    litecoind_exe: PathBuf,
) -> Result<(PathBuf, PathBuf, RpcClient, String, u16, Child)> {
    if !litecoind_exe.exists() {
        bail!("litecoind not found at {}", litecoind_exe.display());
    }

    let datadir = tempfile::tempdir()?.keep();
    let rpc_port = free_port()?;
    let p2p_port = free_port()?;
    let cookie = datadir.join("regtest").join(".cookie");

    let mut litecoind = Command::new(&litecoind_exe)
        .arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-port={p2p_port}"))
        .arg(format!("-rpcport={rpc_port}"))
        .arg("-server=1")
        .arg("-txindex=1")
        .arg("-fallbackfee=0.0001")
        .arg("-acceptnonstdtxn=1")
        .arg("-mempoolreplacement=1")
        // Match Core functional tests: allow MWEB light-client getdata without bans.
        .arg("-whitelist=noban@127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn litecoind")?;

    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");
    let deadline = Instant::now() + Duration::from_secs(60);
    let (user, pass) = loop {
        if Instant::now() > deadline {
            let _ = litecoind.kill();
            bail!("timed out waiting for litecoind cookie");
        }
        if let Ok(contents) = fs::read_to_string(&cookie) {
            if let Some((u, p)) = contents.split_once(':') {
                break (u.to_string(), p.to_string());
            }
        }
        thread::sleep(Duration::from_millis(100));
    };

    let rpc = RpcClient::new(&rpc_url, user, pass);
    while Instant::now() < deadline {
        if rpc.get_blockchain_info().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    rpc.get_blockchain_info()
        .context("litecoind RPC never became ready")?;
    rpc.create_wallet("bdk")?;

    Ok((datadir, cookie, rpc, rpc_url, p2p_port, litecoind))
}

impl LitecoinTestEnv {
    /// Spawn from `LITECOIND_EXE` and `ELECTRS_LTC_EXE`.
    pub fn from_env() -> Result<Self> {
        let litecoind = std::env::var("LITECOIND_EXE")
            .map_err(|_| anyhow!("LITECOIND_EXE is not set; skipping Litecoin regtest harness"))?;
        let electrs = std::env::var("ELECTRS_LTC_EXE").map_err(|_| {
            anyhow!("ELECTRS_LTC_EXE is not set; skipping Litecoin regtest harness")
        })?;
        Self::spawn(PathBuf::from(litecoind), PathBuf::from(electrs))
    }

    pub fn spawn(litecoind_exe: PathBuf, electrs_exe: PathBuf) -> Result<Self> {
        if !electrs_exe.exists() {
            bail!("electrs-ltc not found at {}", electrs_exe.display());
        }

        let (datadir, cookie, rpc, rpc_url, _p2p_port, mut litecoind) =
            spawn_litecoind(litecoind_exe)?;
        let electrum_port = free_port()?;
        let contents = fs::read_to_string(&cookie).context("read litecoind cookie")?;
        let (user, pass) = contents
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed litecoind cookie"))?;

        // RPC URL port is already bound; recover daemon RPC addr from rpc_url.
        let rpc_addr = rpc_url
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();

        let electrs_db = datadir.join("electrs");
        fs::create_dir_all(&electrs_db)?;
        let mut electrs = Command::new(&electrs_exe)
            .arg("--network")
            .arg("regtest")
            .arg("--daemon-dir")
            .arg(&datadir)
            .arg("--db-dir")
            .arg(&electrs_db)
            .arg("--daemon-rpc-addr")
            .arg(&rpc_addr)
            .arg("--electrum-rpc-addr")
            .arg(format!("127.0.0.1:{electrum_port}"))
            .arg("--cookie")
            .arg(format!("{user}:{pass}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn electrs-ltc")?;

        let electrum_host = format!("127.0.0.1:{electrum_port}");
        let electrum_url = format!("tcp://{electrum_host}");
        if let Err(e) = wait_for_tcp(&electrum_host, Duration::from_secs(60)) {
            let _ = electrs.kill();
            let _ = litecoind.kill();
            let _ = electrs.wait();
            let _ = litecoind.wait();
            let _ = fs::remove_dir_all(&datadir);
            return Err(e.context(format!("electrs-ltc never opened {electrum_url}")));
        }

        let env = Self {
            datadir,
            rpc,
            electrum_url,
            rpc_url,
            electrum_host,
            litecoind,
            electrs,
        };

        if let Err(e) = env.wait_until_electrum_sees_block(Duration::from_secs(60)) {
            drop(env);
            return Err(e);
        }

        Ok(env)
    }

    pub fn mine_blocks(&self, n: u32, address: Option<Address>) -> Result<Vec<BlockHash>> {
        let addr = match address {
            Some(a) => a,
            None => self.rpc.get_new_address()?,
        };
        self.rpc.generate_to_address(n, &addr)
    }

    pub fn send(&self, address: &Address, amount: Amount) -> Result<Txid> {
        self.rpc.send_to_address(address, amount)
    }

    pub fn genesis_hash(&self) -> Result<BlockHash> {
        self.rpc.get_block_hash(0)
    }

    pub fn invalidate_blocks(&self, count: u32) -> Result<()> {
        let mut hash = self.rpc.get_best_block_hash()?;
        for _ in 0..count {
            let block = self.rpc.get_block(&hash)?;
            self.rpc.invalidate_block(&hash)?;
            hash = block.header.prev_blockhash;
        }
        Ok(())
    }

    pub fn reorg(&self, count: u32) -> Result<Vec<BlockHash>> {
        let start_height = self.rpc.get_block_count()?;
        self.invalidate_blocks(count)?;
        let res = self.mine_blocks(count, None)?;
        let end_height = self.rpc.get_block_count()?;
        if end_height != start_height {
            bail!("reorg should not change height (was {start_height}, now {end_height})");
        }
        Ok(res)
    }

    /// Poll until electrs tip height matches `litecoind`.
    pub fn wait_until_electrum_sees_block(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let node_height = self.rpc.get_block_count()?;
            if let Ok(v) = electrum_call(
                &self.electrum_host,
                "blockchain.headers.subscribe",
                json!([]),
            ) {
                let tip = v["height"].as_u64().unwrap_or(u64::MAX) as u32;
                if tip == node_height {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        bail!("timed out waiting for electrs tip to match litecoind")
    }
}

impl Drop for LitecoinTestEnv {
    fn drop(&mut self) {
        let _ = self.electrs.kill();
        let _ = self.litecoind.kill();
        let _ = self.electrs.wait();
        let _ = self.litecoind.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

/// Return `Ok(None)` when binaries are not configured.
pub fn try_from_env() -> Result<Option<LitecoinTestEnv>> {
    match LitecoinTestEnv::from_env() {
        Ok(env) => Ok(Some(env)),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("is not set") {
                eprintln!("skip: {msg}");
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}
