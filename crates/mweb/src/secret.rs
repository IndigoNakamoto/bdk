//! Best-effort in-memory protection for 32-byte secrets.
//!
//! MWEB blinding factors, shared secrets, and one-time spend keys are all
//! 32-byte scalars, and they are spend-equivalent: anything that can read them
//! can steal the coin. [`Secret32`] wraps such a scalar so that it wipes itself
//! on drop, compares in constant time, and refuses to print itself.
//!
//! # What this does not do
//!
//! Zeroization in Rust is best effort and nothing more. A secret is still
//! exposed by every move (the compiler is free to leave the old copy behind),
//! by `Vec` reallocation, by paging to swap or a hibernation image, and by a
//! core dump. This module narrows the window during which a secret sits in
//! freed heap memory; it does not close it. Callers that need a stronger
//! guarantee must lock pages and disable core dumps at the process level, which
//! is the application's job, not this crate's.

use zeroize::Zeroize;

/// A 32-byte secret scalar that is wiped on drop.
///
/// Comparison is constant time and [`core::fmt::Debug`] prints `Secret32(..)`,
/// so a stray `{:?}` in a log line cannot leak key material.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Wrap raw bytes. The caller's copy is not wiped — prefer [`Secret32::take`].
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wrap `bytes` and wipe the caller's copy.
    pub fn take(bytes: &mut [u8; 32]) -> Self {
        let out = Self(*bytes);
        bytes.zeroize();
        out
    }

    /// Borrow the secret bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy the secret bytes out. The copy is no longer wiped on drop.
    pub fn expose_copy(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Secret32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret32(..)")
    }
}

impl PartialEq for Secret32 {
    fn eq(&self, other: &Self) -> bool {
        ct_eq32(&self.0, &other.0)
    }
}

impl Eq for Secret32 {}

/// Constant-time equality for 32-byte secrets.
///
/// Timing-safe comparison matters wherever an attacker can observe how long a
/// mismatch took and use that to recover a secret byte by byte. The volatile
/// reads stop LLVM from turning the fold back into an early-exit `memcmp`.
pub fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        // SAFETY: `i` is in bounds for both arrays by construction.
        let (x, y) = unsafe {
            (
                core::ptr::read_volatile(a.as_ptr().add(i)),
                core::ptr::read_volatile(b.as_ptr().add(i)),
            )
        };
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time equality for two optional 32-byte secrets.
///
/// `None` vs `Some` is distinguishable — only the byte comparison is masked,
/// since the presence of a spend key is not itself secret.
pub fn ct_eq32_opt(a: &Option<[u8; 32]>, b: &Option<[u8; 32]>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => ct_eq32(x, y),
        (None, None) => true,
        _ => false,
    }
}

/// Wire-identical to a bare `[u8; 32]`, so a field can switch to `Secret32`
/// without changing any on-disk changeset.
#[cfg(feature = "serde")]
impl serde::Serialize for Secret32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Secret32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <[u8; 32] as serde::Deserialize>::deserialize(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_secret() {
        let s = Secret32::new([0xab; 32]);
        let rendered = alloc::format!("{s:?}");
        assert_eq!(rendered, "Secret32(..)");
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn take_wipes_the_callers_copy() {
        let mut raw = [7u8; 32];
        let s = Secret32::take(&mut raw);
        assert_eq!(raw, [0u8; 32]);
        assert_eq!(s.expose(), &[7u8; 32]);
    }

    #[test]
    fn ct_eq_matches_plain_eq() {
        let a = [1u8; 32];
        let mut b = [1u8; 32];
        assert!(ct_eq32(&a, &b));
        b[31] ^= 1;
        assert!(!ct_eq32(&a, &b));
        b[31] ^= 1;
        b[0] ^= 0x80;
        assert!(!ct_eq32(&a, &b));
    }

    #[test]
    fn ct_eq_opt_distinguishes_presence() {
        assert!(ct_eq32_opt(&None, &None));
        assert!(!ct_eq32_opt(&Some([0u8; 32]), &None));
        assert!(ct_eq32_opt(&Some([9u8; 32]), &Some([9u8; 32])));
        assert!(!ct_eq32_opt(&Some([9u8; 32]), &Some([8u8; 32])));
    }

    #[test]
    fn secret32_equality_is_value_equality() {
        assert_eq!(Secret32::new([3; 32]), Secret32::new([3; 32]));
        assert_ne!(Secret32::new([3; 32]), Secret32::new([4; 32]));
    }
}
