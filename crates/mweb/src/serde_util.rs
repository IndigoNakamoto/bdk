//! Serde helpers for fixed-size byte arrays larger than 32.

use alloc::vec::Vec;
use core::convert::TryInto;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

/// Serialize `[u8; N]` as a byte sequence.
pub fn serialize_bytes<S, const N: usize>(data: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(data.as_slice())
}

/// Deserialize `[u8; N]` from bytes or a sequence of u8.
pub fn deserialize_bytes<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct ByteArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "a byte array of length {N}")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut buf = [0u8; N];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            Ok(buf)
        }
    }

    deserializer.deserialize_bytes(ByteArrayVisitor)
}

/// Module for `#[serde(with = "crate::serde_util::bytes33")]`.
pub mod bytes33 {
    use super::*;
    pub fn serialize<S: Serializer>(data: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(data, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        deserialize_bytes(d)
    }
}
