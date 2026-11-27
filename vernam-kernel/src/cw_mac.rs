//! Injective 15-byte-limb domain-separated Carter-Wegman MAC and affine move-only `OneTimeCwKey`.

use core::fmt;
use core::hint::black_box;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::field::{PRIME_P, add_mod, ct_eq_16, is_canonical, mul_mod, reduce};

/// Errors produced by one-time Carter-Wegman MAC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwMacError {
    /// Key element `r` or `s` was outside canonical `[0, PRIME_P)` (or `r == 0`).
    NonCanonicalKey,
    /// Provided tag decoded to a value `>= PRIME_P`.
    NonCanonicalTag,
    /// Constant-time tag verification failed.
    InvalidTag,
}

/// Evaluate an injective, domain-separated universal polynomial hash over arbitrary bytes.
///
/// Packs `msg` into lossless 15-byte little-endian limbs (`< 2^120 < PRIME_P`) and explicitly
/// binds both `domain` and `msg.len()` so trailing zero bytes or differing lengths never collide.
pub fn poly_hash_bytes(r: u128, domain: u128, msg: &[u8]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(msg.len() as u128));

    let mut offset = 0usize;
    while offset < msg.len() {
        let mut limb = [0u8; 16];
        let mut j = 0usize;
        while j < 15 && offset + j < msg.len() {
            limb[j] = msg[offset + j];
            j += 1;
        }
        acc = add_mod(mul_mod(acc, r), u128::from_le_bytes(limb));
        offset += 15;
    }
    mul_mod(acc, r)
}

/// Evaluate a domain-separated universal polynomial hash over a slice of field elements.
pub fn poly_hash_elems(r: u128, domain: u128, elems: &[u128]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(elems.len() as u128));
    let mut i = 0usize;
    while i < elems.len() {
        acc = add_mod(mul_mod(acc, r), reduce(elems[i]));
        i += 1;
    }
    mul_mod(acc, r)
}

/// Affine move-only one-time Carter-Wegman MAC key `(r, s)` in `F_(2^127 - 1)`.
///
/// Implements neither `Copy` nor `Clone`; every `mac_*` / `verify_*` method takes `self` by value
/// so the Rust type system statically enforces single-use discipline. Redacts `Debug` and scrubs
/// secret key material on `Drop` without `unsafe`.
pub struct OneTimeCwKey {
    r: u128,
    s: u128,
}

impl OneTimeCwKey {
    /// Construct a validated one-time key with `1 <= r < PRIME_P` and `0 <= s < PRIME_P`.
    pub const fn new(r: u128, s: u128) -> Result<Self, CwMacError> {
        if r == 0 || !is_canonical(r) || !is_canonical(s) {
            return Err(CwMacError::NonCanonicalKey);
        }
        Ok(Self { r, s })
    }

    /// Authenticate `msg` under `domain`, consuming and scrubbing this one-time key.
    pub fn mac_bytes(self, domain: u128, msg: &[u8]) -> [u8; 16] {
        let tag = add_mod(poly_hash_bytes(self.r, domain, msg), self.s);
        tag.to_le_bytes()
    }

    /// Verify a 16-byte MAC tag over `msg` in constant time, consuming and scrubbing this key.
    pub fn verify_bytes(
        self,
        domain: u128,
        msg: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), CwMacError> {
        let raw_tag = u128::from_le_bytes(*tag);
        if raw_tag >= PRIME_P {
            return Err(CwMacError::NonCanonicalTag);
        }
        let expected = add_mod(poly_hash_bytes(self.r, domain, msg), self.s).to_le_bytes();
        if ct_eq_16(&expected, tag) {
            Ok(())
        } else {
            Err(CwMacError::InvalidTag)
        }
    }

    /// Authenticate field elements under `domain`, consuming and scrubbing this key.
    pub fn mac_elems(self, domain: u128, elems: &[u128]) -> u128 {
        add_mod(poly_hash_elems(self.r, domain, elems), self.s)
    }

    /// Verify a field-element MAC tag in constant time, consuming and scrubbing this key.
    pub fn verify_elems(
        self,
        domain: u128,
        elems: &[u128],
        tag: u128,
    ) -> Result<(), CwMacError> {
        if tag >= PRIME_P {
            return Err(CwMacError::NonCanonicalTag);
        }
        let expected = add_mod(poly_hash_elems(self.r, domain, elems), self.s);
        if ct_eq_16(&expected.to_le_bytes(), &tag.to_le_bytes()) {
            Ok(())
        } else {
            Err(CwMacError::InvalidTag)
        }
    }
}

impl Drop for OneTimeCwKey {
    fn drop(&mut self) {
        self.r = black_box(0);
        self.s = black_box(0);
        compiler_fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for OneTimeCwKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimeCwKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cw_mac_injective_domain_separation_and_canonical_rejection() {
        assert_eq!(OneTimeCwKey::new(0, 1).unwrap_err(), CwMacError::NonCanonicalKey);
        assert_eq!(OneTimeCwKey::new(PRIME_P, 1).unwrap_err(), CwMacError::NonCanonicalKey);

        let r = 0x1122_3344_5566_7788_99AA_BBCC_DDEE_0011u128 & PRIME_P;
        let s = 0x0F0E_0D0C_0B0A_0908_0706_0504_0302_0100u128 & PRIME_P;

        let k_sign = OneTimeCwKey::new(r, s).unwrap();
        let k_ver = OneTimeCwKey::new(r, s).unwrap();
        let msg = b"vernam-kernel-15-byte-limb-injection-test";
        let tag = k_sign.mac_bytes(1, msg);
        assert!(k_ver.verify_bytes(1, msg, &tag).is_ok());

        // Trailing zero byte produces a distinct tag (length binding).
        let k_zero_a = OneTimeCwKey::new(r, s).unwrap();
        let k_zero_b = OneTimeCwKey::new(r, s).unwrap();
        assert_ne!(k_zero_a.mac_bytes(1, b"abc"), k_zero_b.mac_bytes(1, b"abc\0"));

        // Domain separation produces a distinct tag.
        let k_dom_a = OneTimeCwKey::new(r, s).unwrap();
        let k_dom_b = OneTimeCwKey::new(r, s).unwrap();
        assert_ne!(k_dom_a.mac_bytes(1, msg), k_dom_b.mac_bytes(2, msg));

        // Malleable tag + PRIME_P rejected as non-canonical.
        let k_mal = OneTimeCwKey::new(r, s).unwrap();
        let bad_tag = (u128::from_le_bytes(tag) + PRIME_P).to_le_bytes();
        assert_eq!(k_mal.verify_bytes(1, msg, &bad_tag), Err(CwMacError::NonCanonicalTag));

        // Element MAC roundtrip & tamper rejection.
        let ke_s = OneTimeCwKey::new(r, s).unwrap();
        let ke_v = OneTimeCwKey::new(r, s).unwrap();
        let etag = ke_s.mac_elems(7, &[10, 20, 30]);
        assert!(ke_v.verify_elems(7, &[10, 20, 30], etag).is_ok());
        let ke_bad = OneTimeCwKey::new(r, s).unwrap();
        assert_eq!(ke_bad.verify_elems(7, &[10, 21, 30], etag), Err(CwMacError::InvalidTag));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn prove_cw_mac_roundtrip_and_non_canonical_rejection() {
        let r: u128 = kani::any();
        let s: u128 = kani::any();
        kani::assume(r > 0 && r < PRIME_P);
        kani::assume(s < PRIME_P);
        let msg: [u8; 4] = kani::any();
        let domain: u128 = kani::any();

        let k1 = OneTimeCwKey::new(r, s).unwrap();
        let k2 = OneTimeCwKey::new(r, s).unwrap();
        let tag = k1.mac_bytes(domain, &msg);
        assert!(u128::from_le_bytes(tag) < PRIME_P);
        assert!(k2.verify_bytes(domain, &msg, &tag).is_ok());
    }
}
