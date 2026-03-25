#![deny(clippy::all)]
#![allow(unexpected_cfgs)]

use sha2::{Digest, Sha256};
use solana_secp256k1::{CompressedPoint, Curve, Secp256k1Point, UncompressedPoint};

const SUITE_BYTE: u8 = 0xFE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcvrfError {
    InvalidProofLength,
    InvalidPoint,
    InvalidScalar,
    EncodeToCurveFailed,
    VerificationFailed,
    InvalidInstructionData,
}

fn point_to_compressed(point: &UncompressedPoint) -> [u8; 33] {
    CompressedPoint::from(*point).0
}

/// RFC 9381 Section 5.4.1.1 — try_and_increment hash-to-curve.
fn encode_to_curve(pk: &[u8; 33], alpha: &[u8]) -> Result<CompressedPoint, EcvrfError> {
    for ctr in 0..=255u8 {
        let hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([SUITE_BYTE, 0x01]);
            h.update(pk);
            h.update(alpha);
            h.update([ctr, 0x00]);
            h.finalize().into()
        };

        let mut candidate = [0u8; 33];
        candidate[0] = 0x02;
        candidate[1..].copy_from_slice(&hash);
        let point = CompressedPoint(candidate);

        if Curve::decompress(point).is_ok() {
            return Ok(point);
        }
    }
    Err(EcvrfError::EncodeToCurveFailed)
}

/// RFC 9381 Section 5.4.3 — 5-point challenge generation.
fn challenge_generation(
    y: &[u8; 33],
    h: &[u8; 33],
    gamma: &[u8; 33],
    u: &[u8; 33],
    v: &[u8; 33],
) -> [u8; 16] {
    let hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update([SUITE_BYTE, 0x02]);
        hasher.update(y);
        hasher.update(h);
        hasher.update(gamma);
        hasher.update(u);
        hasher.update(v);
        hasher.update([0x00]);
        hasher.finalize().into()
    };
    let mut c = [0u8; 16];
    c.copy_from_slice(&hash[..16]);
    c
}

/// RFC 9381 Section 5.2 — proof_to_hash (derive beta from Gamma).
fn proof_to_hash_inner(gamma: &[u8; 33]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_BYTE, 0x03]);
    hasher.update(gamma);
    hasher.update([0x00]);
    hasher.finalize().into()
}

fn pad_c(c: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(c);
    out
}

fn lt_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// Verify an ECVRF proof per RFC 9381 Section 5.3.
///
/// Takes a compressed public key (33 bytes), proof (81 bytes), and alpha string.
/// Returns beta (32-byte VRF output) on success.
pub fn verify(pk: &[u8; 33], pi: &[u8; 81], alpha: &[u8]) -> Result<[u8; 32], EcvrfError> {
    let mut gamma_bytes = [0u8; 33];
    gamma_bytes.copy_from_slice(&pi[..33]);
    let mut c_bytes = [0u8; 16];
    c_bytes.copy_from_slice(&pi[33..49]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pi[49..81]);

    if gamma_bytes[0] != 0x02 && gamma_bytes[0] != 0x03 {
        return Err(EcvrfError::InvalidPoint);
    }
    let gamma = CompressedPoint(gamma_bytes);
    Curve::decompress(gamma).map_err(|_| EcvrfError::InvalidPoint)?;

    if !lt_be(&s_bytes, &Curve::N) {
        return Err(EcvrfError::InvalidScalar);
    }

    let y = CompressedPoint(*pk);

    let h = encode_to_curve(pk, alpha)?;

    // U = s*G - c*Y via single secp256k1_recover call.
    //
    // ecrecover(z, v, [r, s_sig]) returns r⁻¹(s_sig·R − z·G) where R is
    // identified by (r = Y.x, v = Y.is_odd()).
    //
    // Choose:  z     = −(Y.x · s) mod n
    //          s_sig = −(Y.x · c) mod n
    //
    // Then: r⁻¹(s_sig·Y − z·G)
    //     = Y.x⁻¹(−Y.x·c·Y + Y.x·s·G)
    //     = s·G − c·Y
    let c_padded = pad_c(&c_bytes);
    let y_x = y.x();
    let z_u = Curve::negate_n(&Curve::mul_mod_n(&y_x, &s_bytes));
    let s_u = Curve::negate_n(&Curve::mul_mod_n(&y_x, &c_padded));
    let mut sig_u = [0u8; 64];
    sig_u[..32].copy_from_slice(&y_x);
    sig_u[32..].copy_from_slice(&s_u);

    let u_raw = solana_nostd_secp256k1_recover::secp256k1_recover(&z_u, y.is_odd(), &sig_u)
        .map_err(|_| EcvrfError::InvalidPoint)?;
    let u_compressed = point_to_compressed(&UncompressedPoint(u_raw));

    // V = s*H − c*Gamma  via two ecmuls + point addition.
    let n_minus_c = Curve::negate_n(&c_padded);
    let s_h = Curve::ecmul(&h, &s_bytes).map_err(|_| EcvrfError::InvalidPoint)?;
    let neg_c_gamma =
        Curve::ecmul(&gamma, &n_minus_c).map_err(|_| EcvrfError::InvalidPoint)?;
    let v_point = s_h + neg_c_gamma;
    let v_compressed = point_to_compressed(&v_point);

    let c_prime = challenge_generation(pk, &h.0, &gamma_bytes, &u_compressed, &v_compressed);

    if c_bytes == c_prime {
        Ok(proof_to_hash_inner(&gamma_bytes))
    } else {
        Err(EcvrfError::VerificationFailed)
    }
}

/// Extract VRF output (beta) from a proof without full verification.
pub fn proof_to_hash(pi: &[u8; 81]) -> Result<[u8; 32], EcvrfError> {
    if pi[0] != 0x02 && pi[0] != 0x03 {
        return Err(EcvrfError::InvalidPoint);
    }
    let mut gamma = [0u8; 33];
    gamma.copy_from_slice(&pi[..33]);
    let p = CompressedPoint(gamma);
    Curve::decompress(p).map_err(|_| EcvrfError::InvalidPoint)?;
    Ok(proof_to_hash_inner(&gamma))
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult,
        program::set_return_data, program_error::ProgramError, pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        if data.len() < 114 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let pk: &[u8; 33] = data[..33]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let pi: &[u8; 81] = data[33..114]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let alpha = &data[114..];

        let beta = crate::verify(pk, pi, alpha).map_err(|_| ProgramError::InvalidArgument)?;

        set_return_data(&beta);
        Ok(())
    }
}
