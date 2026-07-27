//! LIP-0004 / Litecoin Core MWEB key derivation.
//!
//! Default HD paths match Litecoin Core 0.21 `LoadMWEBKeychain`:
//! - scan:  `m/0'/100'/0'`
//! - spend: `m/0'/100'/1'`
//!
//! Subaddress tweak matches production `mw::Keychain::GetSpendKey`:
//! `mi = BLAKE3('A' || LE32(index) || scan_secret)`.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar, SecretKey};
use bitcoin::{Network, NetworkKind};

use crate::error::Error;

/// Tag byte `EHashTag::ADDRESS` from Core `Hasher.h`.
const TAG_ADDRESS: u8 = b'A';

/// Which BIP32 layout to use for master scan/spend keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeyScheme {
    /// Litecoin Core 0.21: `m/0'/100'/{0,1}'`.
    LitecoinCore,
    /// LIP-0004 text: `m/1/0/100'` and `m/1/0/101'` (non-hardened middle components).
    Lip0004,
}

impl Default for MasterKeyScheme {
    fn default() -> Self {
        Self::LitecoinCore
    }
}

/// Master scan (`a`) and spend (`b`) secrets for an MWEB account.
#[derive(Clone)]
pub struct MasterKeys {
    /// Scan private key `a`.
    pub scan: SecretKey,
    /// Spend private key `b`.
    pub spend: SecretKey,
    /// Scheme used to derive these keys.
    pub scheme: MasterKeyScheme,
}

impl MasterKeys {
    /// Derive master keys from a BIP32 seed (typically 16–64 bytes).
    pub fn from_seed(
        seed: &[u8],
        network: Network,
        scheme: MasterKeyScheme,
        secp: &Secp256k1<All>,
    ) -> Result<Self, Error> {
        let master = Xpriv::new_master(network, seed)?;
        let (scan_path, spend_path) = match scheme {
            MasterKeyScheme::LitecoinCore => (
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(0)?,
                    ChildNumber::from_hardened_idx(100)?,
                    ChildNumber::from_hardened_idx(0)?,
                ]),
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(0)?,
                    ChildNumber::from_hardened_idx(100)?,
                    ChildNumber::from_hardened_idx(1)?,
                ]),
            ),
            MasterKeyScheme::Lip0004 => (
                // m/1/0/100' — LIP text uses a hardened final component.
                DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(1)?,
                    ChildNumber::from_normal_idx(0)?,
                    ChildNumber::from_hardened_idx(100)?,
                ]),
                DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(1)?,
                    ChildNumber::from_normal_idx(0)?,
                    ChildNumber::from_hardened_idx(101)?,
                ]),
            ),
        };
        let scan = master.derive_priv(secp, &scan_path)?.private_key;
        let spend = master.derive_priv(secp, &spend_path)?.private_key;
        Ok(Self {
            scan,
            spend,
            scheme,
        })
    }

    /// Master scan public key `A = a·G`.
    pub fn scan_public(&self, secp: &Secp256k1<All>) -> PublicKey {
        PublicKey::from_secret_key(secp, &self.scan)
    }

    /// Master spend public key `B = b·G`.
    pub fn spend_public(&self, secp: &Secp256k1<All>) -> PublicKey {
        PublicKey::from_secret_key(secp, &self.spend)
    }

    /// One-time spend secret `b_i` for address index `i` (Core `GetSpendKey`).
    pub fn spend_key_at(&self, index: u32) -> Result<SecretKey, Error> {
        let mi = address_index_tweak(&self.scan, index);
        let tweak = Scalar::from_be_bytes(mi).map_err(|_| Error::InvalidTweak)?;
        Ok(self.spend.add_tweak(&tweak)?)
    }

    /// Stealth address pubkeys `(A_i, B_i)` for index `i`.
    pub fn stealth_pubkeys(
        &self,
        index: u32,
        secp: &Secp256k1<All>,
    ) -> Result<(PublicKey, PublicKey), Error> {
        let b_i = self.spend_key_at(index)?;
        let b_i_pk = PublicKey::from_secret_key(secp, &b_i);
        // A_i = a · B_i  (Core: Bi.Mul(m_scanSecret))
        let scan_scalar =
            Scalar::from_be_bytes(self.scan.secret_bytes()).map_err(|_| Error::InvalidTweak)?;
        let a_i_pk = b_i_pk.mul_tweak(secp, &scan_scalar)?;
        Ok((a_i_pk, b_i_pk))
    }

    /// Build a Litecoin MWEB [`Address`](bitcoin::Address) for `index`.
    pub fn address(
        &self,
        index: u32,
        network: impl Into<NetworkKind>,
        secp: &Secp256k1<All>,
    ) -> Result<bitcoin::Address, Error> {
        let (scan_pk, spend_pk) = self.stealth_pubkeys(index, secp)?;
        Ok(bitcoin::Address::mweb(scan_pk, spend_pk, network))
    }
}

/// Core `Hasher(EHashTag::ADDRESS).Append(index).Append(scan_secret)`.
pub fn address_index_tweak(scan_secret: &SecretKey, index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[TAG_ADDRESS]);
    hasher.update(&index.to_le_bytes());
    hasher.update(&scan_secret.secret_bytes());
    *hasher.finalize().as_bytes()
}

/// Convenience: Core scheme from seed on `network`.
pub fn master_keys_from_seed(
    seed: &[u8],
    network: Network,
) -> Result<MasterKeys, Error> {
    let secp = Secp256k1::new();
    MasterKeys::from_seed(seed, network, MasterKeyScheme::LitecoinCore, &secp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn spend_key_tweak_is_deterministic() {
        let secp = Secp256k1::new();
        let seed = [0x42u8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let b0 = keys.spend_key_at(0).unwrap();
        let b0_again = keys.spend_key_at(0).unwrap();
        assert_eq!(b0, b0_again);
        assert_ne!(b0, keys.spend_key_at(1).unwrap());
    }

    #[test]
    fn stealth_scan_pubkey_matches_a_times_bi() {
        let secp = Secp256k1::new();
        let seed = [0x11u8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let (a_i, b_i) = keys.stealth_pubkeys(7, &secp).unwrap();
        let scan_scalar = Scalar::from_be_bytes(keys.scan.secret_bytes()).unwrap();
        let expected = b_i.mul_tweak(&secp, &scan_scalar).unwrap();
        assert_eq!(a_i, expected);
    }

    #[test]
    fn address_round_trips_bech32() {
        let secp = Secp256k1::new();
        let seed = [0xAAu8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let addr = keys.address(0, NetworkKind::Test, &secp).unwrap();
        let encoded = addr.to_string();
        assert!(
            encoded.starts_with("tmweb1"),
            "regtest/testnet MWEB HRP, got {encoded}"
        );
        let parsed = encoded
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(parsed.address_type(), Some(bitcoin::AddressType::Mweb));
    }

    #[test]
    fn known_vector_core_scheme_index_zero() {
        use hex_conservative::{DisplayHex, FromHex};

        let secp = Secp256k1::new();
        let seed = <[u8; 32]>::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let tweak = address_index_tweak(&keys.scan, 0);
        assert_eq!(
            tweak.to_lower_hex_string(),
            "aaf21a8b396e678466d1b90d5503981128e7fd633983b77b538f23707c7e2de9"
        );
        assert_eq!(
            keys.address(0, NetworkKind::Test, &secp).unwrap().to_string(),
            "tmweb1qqvyk2xmvquxe9qhnfk9cn7zd4ahyelaj233mly7nyacxnc8ejt2dxq69frwmgdf09hkc68dlllwhz3as06t4e2tshrzv9ucp9a647nwztuxmecr2"
        );
        assert_eq!(
            keys.address(2, NetworkKind::Test, &secp).unwrap().to_string(),
            "tmweb1qqwzy5see3nhfrackv6fzqge4462q08zv809te0v3spr3wllxahgmuqmjp4r58m2n9mwtvxrey6l9ejpantlefwgwr557t08ew6ufsg0d0gmucskp"
        );
    }
}
