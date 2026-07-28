//! LIP-0004 / Litecoin Core MWEB key derivation.
//!
//! Default HD paths match Litecoin Core 0.21 `LoadMWEBKeychain`:
//! - scan:  `m/0'/100'/0'`
//! - spend: `m/0'/100'/1'`
//!
//! Subaddress tweak matches production `mw::Keychain::GetSpendKey`:
//! `mi = BLAKE3('A' || LE32(index) || scan_secret)`.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar, SecretKey};
use bitcoin::{Network, NetworkKind};

use crate::error::Error;

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

impl MasterKeyScheme {
    /// Scan-key derivation path for this scheme.
    pub fn scan_path(self) -> Result<DerivationPath, Error> {
        Ok(match self {
            Self::LitecoinCore => DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(0)?,
                ChildNumber::from_hardened_idx(100)?,
                ChildNumber::from_hardened_idx(0)?,
            ]),
            Self::Lip0004 => DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1)?,
                ChildNumber::from_normal_idx(0)?,
                ChildNumber::from_hardened_idx(100)?,
            ]),
        })
    }

    /// Spend-key derivation path for this scheme.
    pub fn spend_path(self) -> Result<DerivationPath, Error> {
        Ok(match self {
            Self::LitecoinCore => DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(0)?,
                ChildNumber::from_hardened_idx(100)?,
                ChildNumber::from_hardened_idx(1)?,
            ]),
            Self::Lip0004 => DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1)?,
                ChildNumber::from_normal_idx(0)?,
                ChildNumber::from_hardened_idx(101)?,
            ]),
        })
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
    /// BIP32 master fingerprint of the seed used to derive these keys.
    pub master_fingerprint: Fingerprint,
    /// Full derivation path to the scan key.
    pub scan_path: DerivationPath,
    /// Full derivation path to the spend key.
    pub spend_path: DerivationPath,
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
        let fingerprint = master.fingerprint(secp);
        let scan_path = scheme.scan_path()?;
        let spend_path = scheme.spend_path()?;
        let scan = master.derive_priv(secp, &scan_path)?.private_key;
        let spend = master.derive_priv(secp, &spend_path)?.private_key;
        Ok(Self {
            scan,
            spend,
            scheme,
            master_fingerprint: fingerprint,
            scan_path,
            spend_path,
        })
    }

    /// BIP32 [`KeySource`] for the master scan key (`0x9A`).
    pub fn scan_key_source(&self) -> KeySource {
        (self.master_fingerprint, self.scan_path.clone())
    }

    /// BIP32 [`KeySource`] for the master spend key (`0x9B`).
    pub fn spend_key_source(&self) -> KeySource {
        (self.master_fingerprint, self.spend_path.clone())
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
    use crate::hash::HashTag;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[HashTag::Address as u8]);
    hasher.update(&index.to_le_bytes());
    hasher.update(&scan_secret.secret_bytes());
    *hasher.finalize().as_bytes()
}

/// Convenience: Core scheme from seed on `network`.
pub fn master_keys_from_seed(seed: &[u8], network: Network) -> Result<MasterKeys, Error> {
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
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
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
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
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
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
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
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
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
        assert_eq!(keys.master_fingerprint, keys.scan_key_source().0);
        assert_eq!(keys.scan_path.to_string(), "0'/100'/0'");
        assert_eq!(keys.spend_path.to_string(), "0'/100'/1'");
    }

    /// Port of ltcd `ltcutil/mweb/keychain_test.go` + ltcwallet `mweb_compat_test.go`.
    #[test]
    fn ltcd_keychain_subaddress_matches_core() {
        use hex_conservative::{DisplayHex, FromHex};

        let secp = Secp256k1::new();
        let seed = <[u8; 32]>::from_hex(
            "2a64df085eefedd8bfdbb33176b5ba2e62e8be8b56c8837795598bb6c440c064",
        )
        .unwrap();
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Bitcoin,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
        .unwrap();

        assert_eq!(
            keys.scan.secret_bytes().to_lower_hex_string(),
            "b3c91b7291c2e1e06d4a93f3dc32404aef9927db8e794c01a7b4de18a397c338"
        );
        assert_eq!(
            keys.spend.secret_bytes().to_lower_hex_string(),
            "2fe1982b98c0b68c0839421c8a0a0a67ef3198c746ab8e6d09101eb7396a44d8"
        );
        // ltcwallet mweb_compat expectedScanPubKey / expectedSpendPubKey
        assert_eq!(
            keys.scan_public(&secp).serialize().to_lower_hex_string(),
            "02cd7e29e31bf0c07281d3c591fe3dbe4375b911cc6038ec5d1be82099d6c482f5"
        );
        assert_eq!(
            keys.spend_public(&secp).serialize().to_lower_hex_string(),
            "03e3908af70085b458020e64aaa5c9a4b8ff382d42af0875c8145db6a30db9cad2"
        );

        let vectors = [
            (
                0u32,
                "03acdfb78943f3330437760e37731828f9abd626a72df16fc7cd968df13b7465ab",
                "039ed000ed69ca7d593f09ad4a373200bc9711261aab56efc05b92a5eab434f864",
                "4076801c591afd06d2823c79858e4c93a6a69ad31ddca673e457437229c74b18",
                "ltcmweb1qqwkdldufg0enxpphwc8rwucc9ru6h43x5uklzm78ektgmufmw3j6kqu76qqw66w204vn7zddfgmnyq9ujugjvx4t2mhuqkuj5h4tgd8cvs6gg076",
            ),
            (
                1,
                "02516a92f3bc6025bce2911e67140dded34ac1f938df0148c9b478e577b5054e42",
                "035dad4451e4f2bfd56bb0266a12d92af4749d43a452471e52a437b9d7bbb157c1",
                "edf509d17a9ebe744dfb77650a4cc39fa90dc6a758c9d33107b2c4a501fa98ab",
                "ltcmweb1qqfgk4yhnh3szt08zjy0xw9qdmmf54s0e8r0szjxfk3uw2aa4q48yyq6a44z9re8jhl2khvpxdgfdj2h5wjw58fzjgu099fphh8tmhv2hcygfr2nl",
            ),
            (
                10,
                "03f864dcaa67a74542ff9b5adc27ad2f9002626baa91372e9aee7737ecfec18cca",
                "027223f04b94617ec15d7d5c135c42242af64b2129f17080e6b10756bb6ec10073",
                "bb33118206a8f8ec35874f78ae5676365bc4e9480d4600947ebb5e049ca4d3e4",
                "ltcmweb1qq0uxfh92v7n52shlndddcfad97gqycnt42gnwt56aemn0m87cxxv5qnjy0cyh9rp0mq46l2uzdwyyfp27e9jz203wzqwdvg826akasgqwvgs2kze",
            ),
        ];

        for (index, scan_a, spend_b, spend_key, encoded) in vectors {
            let (a_i, b_i) = keys.stealth_pubkeys(index, &secp).unwrap();
            assert_eq!(a_i.serialize().to_lower_hex_string(), scan_a);
            assert_eq!(b_i.serialize().to_lower_hex_string(), spend_b);

            let sk = keys.spend_key_at(index).unwrap();
            assert_eq!(sk.secret_bytes().to_lower_hex_string(), spend_key);
            assert_eq!(PublicKey::from_secret_key(&secp, &sk), b_i);

            // Spend + mi(i) == SpendKey(i)
            let mi = address_index_tweak(&keys.scan, index);
            let reconstructed = keys
                .spend
                .add_tweak(&Scalar::from_be_bytes(mi).unwrap())
                .unwrap();
            assert_eq!(reconstructed, sk);

            assert_eq!(
                keys.address(index, NetworkKind::Main, &secp)
                    .unwrap()
                    .to_string(),
                encoded
            );
        }
    }
}
