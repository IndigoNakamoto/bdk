//! MWEB stealth address helpers built on `litecoin::Address`.

use bitcoin::address::{Address, NetworkUnchecked};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::{AddressType, Network, NetworkKind};

use crate::error::Error;
use crate::keys::MasterKeys;

/// Parse an MWEB stealth address string and require `network`.
pub fn parse_mweb_address(s: &str, network: Network) -> Result<Address, Error> {
    let unchecked: Address<NetworkUnchecked> = s.parse().map_err(|_| Error::InvalidTweak)?;
    unchecked
        .require_network(network)
        .map_err(|_| Error::InvalidTweak)
}

/// True if `addr` is an MWEB stealth address.
pub fn is_mweb_address(addr: &Address) -> bool {
    addr.address_type() == Some(AddressType::Mweb)
}

/// Derive the MWEB receive address at `index` (Core scheme by default via [`MasterKeys`]).
pub fn receive_address(
    keys: &MasterKeys,
    index: u32,
    network: impl Into<NetworkKind>,
    secp: &Secp256k1<All>,
) -> Result<Address, Error> {
    keys.address(index, network, secp)
}
