#![deny(clippy::all)]

use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

const SUITE_BYTE: u8 = 0xFE;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("proof must be exactly 81 bytes")]
    InvalidProofLength,
    #[error("invalid elliptic curve point")]
    InvalidPoint,
    #[error("invalid scalar")]
    InvalidScalar,
    #[error("encode_to_curve failed after 256 iterations")]
    EncodeToCurveFailed,
    #[error("proof verification failed")]
    VerificationFailed,
}

fn scalar_from_repr(bytes: [u8; 32]) -> Option<Scalar> {
    let ct = Scalar::from_repr(bytes.into());
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn affine_from_encoded(encoded: &EncodedPoint) -> Option<AffinePoint> {
    let ct = AffinePoint::from_encoded_point(encoded);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// SEC1 compressed point encoding (33 bytes).
fn point_to_string(point: &ProjectivePoint) -> [u8; 33] {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let mut result = [0u8; 33];
    result.copy_from_slice(encoded.as_bytes());
    result
}

/// Decompress a SEC1 compressed point.
fn string_to_point(data: &[u8]) -> Result<ProjectivePoint, Error> {
    let encoded = EncodedPoint::from_bytes(data).map_err(|_| Error::InvalidPoint)?;
    affine_from_encoded(&encoded)
        .map(ProjectivePoint::from)
        .ok_or(Error::InvalidPoint)
}

/// RFC 9381 Section 5.4.1.1 — try_and_increment hash-to-curve.
fn encode_to_curve_tai(
    pk_point: &ProjectivePoint,
    alpha: &[u8],
) -> Result<ProjectivePoint, Error> {
    let pk_bytes = point_to_string(pk_point);
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;

    for ctr in 0..=255u8 {
        let hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([SUITE_BYTE, 0x01]);
            h.update(pk_bytes);
            h.update(alpha);
            h.update([ctr, 0x00]);
            h.finalize().into()
        };
        compressed[1..].copy_from_slice(&hash);

        let encoded = EncodedPoint::from_bytes(&compressed[..])
            .expect("0x02 prefix with 32 coordinate bytes is always valid SEC1 structure");
        if let Some(affine) = affine_from_encoded(&encoded) {
            return Ok(ProjectivePoint::from(affine));
        }
    }
    Err(Error::EncodeToCurveFailed)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RFC 6979 deterministic nonce generation.
///
/// Matches the Python `ecdsa` library's `generate_k` behaviour: the hash
/// digest is NOT reduced modulo the group order before entering the
/// HMAC-DRBG loop (for secp256k1 + SHA-256, hlen == qlen so bits2int is
/// the identity function on the byte string).
fn nonce_generation_rfc6979(sk: &[u8; 32], h_point: &ProjectivePoint) -> Scalar {
    let h_string = point_to_string(h_point);
    let h1: [u8; 32] = Sha256::digest(h_string).into();

    let mut v = [0x01u8; 32];
    let mut k_key = [0x00u8; 32];

    // bx = sk || h1 (64 bytes, no reduction)
    let mut buf = [0u8; 97]; // V(32) + separator(1) + bx(64)
    buf[..32].copy_from_slice(&v);
    buf[32] = 0x00;
    buf[33..65].copy_from_slice(sk);
    buf[65..97].copy_from_slice(&h1);
    k_key = hmac_sha256(&k_key, &buf);

    v = hmac_sha256(&k_key, &v);

    buf[..32].copy_from_slice(&v);
    buf[32] = 0x01;
    k_key = hmac_sha256(&k_key, &buf);

    v = hmac_sha256(&k_key, &v);

    loop {
        v = hmac_sha256(&k_key, &v);
        if let Some(scalar) = scalar_from_repr(v) {
            if scalar != Scalar::ZERO {
                return scalar;
            }
        }
        let mut retry = [0u8; 33];
        retry[..32].copy_from_slice(&v);
        retry[32] = 0x00;
        k_key = hmac_sha256(&k_key, &retry);
        v = hmac_sha256(&k_key, &v);
    }
}

/// RFC 9381 Section 5.4.3 — 5-point challenge generation.
///
/// Includes Y (public key) per RFC 9381; draft-05/06 omitted Y.
fn challenge_generation(
    y: &ProjectivePoint,
    h: &ProjectivePoint,
    gamma: &ProjectivePoint,
    u: &ProjectivePoint,
    v: &ProjectivePoint,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_BYTE, 0x02]);
    hasher.update(point_to_string(y));
    hasher.update(point_to_string(h));
    hasher.update(point_to_string(gamma));
    hasher.update(point_to_string(u));
    hasher.update(point_to_string(v));
    hasher.update([0x00]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut c = [0u8; 16];
    c.copy_from_slice(&hash[..16]);
    c
}

/// Zero-pad a 16-byte challenge to 32 bytes and parse as a Scalar.
/// A 128-bit value is always less than the secp256k1 group order.
fn challenge_to_scalar(c: &[u8; 16]) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(c);
    scalar_from_repr(bytes)
        .expect("128-bit challenge is always less than the 256-bit group order")
}

/// RFC 9381 Section 5.2 — derive VRF output (beta) from Gamma.
/// secp256k1 cofactor is 1, so cofactor multiplication is identity.
fn proof_to_hash_internal(gamma: &ProjectivePoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_BYTE, 0x03]);
    hasher.update(point_to_string(gamma));
    hasher.update([0x00]);
    hasher.finalize().into()
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// Derive the compressed public key (33 bytes) from a secret key.
pub fn derive_public_key(sk: &[u8; 32]) -> Result<[u8; 33], Error> {
    let x = scalar_from_repr(*sk).ok_or(Error::InvalidScalar)?;
    if x == Scalar::ZERO {
        return Err(Error::InvalidScalar);
    }
    Ok(point_to_string(&(ProjectivePoint::GENERATOR * x)))
}

/// Generate a VRF proof per RFC 9381 Section 5.1.
///
/// Returns pi (81 bytes): Gamma(33) || c(16) || s(32).
pub fn prove(sk: &[u8; 32], alpha: &[u8]) -> Result<[u8; 81], Error> {
    let x = scalar_from_repr(*sk).ok_or(Error::InvalidScalar)?;
    if x == Scalar::ZERO {
        return Err(Error::InvalidScalar);
    }

    let y = ProjectivePoint::GENERATOR * x;
    let h = encode_to_curve_tai(&y, alpha)?;
    let gamma = h * x;
    let k = nonce_generation_rfc6979(sk, &h);
    let u = ProjectivePoint::GENERATOR * k;
    let v = h * k;
    let c = challenge_generation(&y, &h, &gamma, &u, &v);
    let c_scalar = challenge_to_scalar(&c);
    let s = k + c_scalar * x;

    let mut pi = [0u8; 81];
    pi[..33].copy_from_slice(&point_to_string(&gamma));
    pi[33..49].copy_from_slice(&c);
    pi[49..81].copy_from_slice(&scalar_to_bytes(&s));
    Ok(pi)
}

/// Verify a VRF proof per RFC 9381 Section 5.3.
///
/// Returns beta (32 bytes, the VRF output) on success.
pub fn verify(pk_bytes: &[u8], pi: &[u8], alpha: &[u8]) -> Result<[u8; 32], Error> {
    if pi.len() != 81 {
        return Err(Error::InvalidProofLength);
    }

    let gamma = string_to_point(&pi[..33])?;
    if bool::from(gamma.is_identity()) {
        return Err(Error::InvalidPoint);
    }

    let c_bytes: [u8; 16] = pi[33..49]
        .try_into()
        .map_err(|_| Error::InvalidProofLength)?;
    let s_bytes: [u8; 32] = pi[49..81]
        .try_into()
        .map_err(|_| Error::InvalidProofLength)?;

    let s = scalar_from_repr(s_bytes).ok_or(Error::InvalidScalar)?;
    let c_scalar = challenge_to_scalar(&c_bytes);

    let y = string_to_point(pk_bytes)?;
    let h = encode_to_curve_tai(&y, alpha)?;

    let u = ProjectivePoint::GENERATOR * s - y * c_scalar;
    let v = h * s - gamma * c_scalar;

    let c_prime = challenge_generation(&y, &h, &gamma, &u, &v);

    if c_bytes == c_prime {
        Ok(proof_to_hash_internal(&gamma))
    } else {
        Err(Error::VerificationFailed)
    }
}

/// Extract VRF output (beta, 32 bytes) from a proof without verification.
pub fn proof_to_hash(pi: &[u8]) -> Result<[u8; 32], Error> {
    if pi.len() != 81 {
        return Err(Error::InvalidProofLength);
    }
    let gamma = string_to_point(&pi[..33])?;
    Ok(proof_to_hash_internal(&gamma))
}
