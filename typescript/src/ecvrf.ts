/**
 * RFC 9381 ECVRF-SECP256K1-SHA256-TAI
 *
 * Verifiable Random Function using secp256k1, SHA-256, and try-and-increment
 * hash-to-curve. Implements the final RFC 9381 standard — not draft-05/06.
 *
 * Suite byte: 0xFE (community convention for secp256k1).
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  bytesToNumberBE,
  concatBytes,
  createHmacDrbg,
  numberToBytesBE,
} from '@noble/curves/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const Point = secp256k1.Point;
type PointType = InstanceType<typeof Point>;
const CURVE_ORDER = Point.CURVE().n;
const SUITE_BYTE = 0xfe;

function pointToBytes(p: PointType): Uint8Array {
  return p.toBytes(true);
}

function bytesToPoint(data: Uint8Array): PointType {
  const p = Point.fromBytes(data);
  p.assertValidity();
  return p;
}

function i2osp(value: bigint, length: number): Uint8Array {
  return numberToBytesBE(value, length);
}

/**
 * RFC 9381 Section 5.4.1.1 — try_and_increment hash-to-curve.
 *
 * Uses even y-coordinate (0x02 prefix) when decompressing candidates.
 */
export function encodeToCurve(
  pkPoint: PointType,
  alpha: Uint8Array,
): { h: PointType; ctr: number } {
  const pkBytes = pointToBytes(pkPoint);
  for (let ctr = 0; ctr < 256; ctr++) {
    const hashInput = concatBytes(
      new Uint8Array([SUITE_BYTE, 0x01]),
      pkBytes,
      alpha,
      new Uint8Array([ctr]),
      new Uint8Array([0x00]),
    );
    const candidate = sha256(hashInput);
    try {
      const compressed = concatBytes(new Uint8Array([0x02]), candidate);
      const point = Point.fromBytes(compressed);
      point.assertValidity();
      return { h: point, ctr };
    } catch {
      continue;
    }
  }
  throw new Error('encode_to_curve: no valid point found in 256 iterations');
}

/**
 * RFC 9381 Section 5.4.2.1 — deterministic nonce via RFC 6979.
 *
 * Per the spec the "message" for RFC 6979 is point_to_string(H).
 * The HMAC-DRBG expects the already-hashed message (h1 = Hash(m)),
 * so we hash point_to_string(H) with SHA-256 first.
 */
function nonceGenerationRFC6979(sk: Uint8Array, hPoint: PointType): bigint {
  const hString = pointToBytes(hPoint);
  const h1 = sha256(hString);
  const qByteLen = 32;
  const hmacFn = (key: Uint8Array, message: Uint8Array): Uint8Array =>
    hmac(sha256, key, message);
  const drbg = createHmacDrbg<bigint>(sha256.outputLen, qByteLen, hmacFn);
  const seed = concatBytes(sk, h1);
  return drbg(seed, (bytes: Uint8Array): bigint | undefined => {
    const k = bytesToNumberBE(bytes);
    if (k > 0n && k < CURVE_ORDER) return k;
    return undefined;
  });
}

/**
 * RFC 9381 Section 5.4.3 — 5-point challenge generation.
 *
 * Includes Y (public key) per RFC 9381; draft-05/06 omitted Y.
 */
export function challengeGeneration(
  y: PointType,
  h: PointType,
  gamma: PointType,
  u: PointType,
  v: PointType,
): bigint {
  const hashInput = concatBytes(
    new Uint8Array([SUITE_BYTE, 0x02]),
    pointToBytes(y),
    pointToBytes(h),
    pointToBytes(gamma),
    pointToBytes(u),
    pointToBytes(v),
    new Uint8Array([0x00]),
  );
  const cString = sha256(hashInput);
  return bytesToNumberBE(cString.slice(0, 16));
}

/**
 * RFC 9381 Section 5.2 — derive VRF output (beta) from Gamma.
 *
 * Cofactor is 1 for secp256k1, so cofactor*Gamma = Gamma.
 */
export function proofToHash(pi: Uint8Array): Uint8Array {
  const { gamma } = decodeProof(pi);
  const hashInput = concatBytes(
    new Uint8Array([SUITE_BYTE, 0x03]),
    pointToBytes(gamma),
    new Uint8Array([0x00]),
  );
  return sha256(hashInput);
}

function encodeProof(gamma: PointType, c: bigint, s: bigint): Uint8Array {
  return concatBytes(pointToBytes(gamma), i2osp(c, 16), i2osp(s, 32));
}

export function decodeProof(pi: Uint8Array): {
  gamma: PointType;
  c: bigint;
  s: bigint;
} {
  if (pi.length !== 81) {
    throw new Error(`proof must be 81 bytes, got ${pi.length}`);
  }
  const gamma = bytesToPoint(pi.slice(0, 33));
  const c = bytesToNumberBE(pi.slice(33, 49));
  const s = bytesToNumberBE(pi.slice(49, 81));
  return { gamma, c, s };
}

/**
 * RFC 9381 Section 5.1 — generate a VRF proof.
 *
 * @param sk - 32-byte secret key (big-endian scalar)
 * @param alpha - arbitrary-length alpha string
 * @returns pi - 81-byte proof: Gamma(33) || c(16) || s(32)
 */
export function prove(sk: Uint8Array, alpha: Uint8Array): Uint8Array {
  const x = bytesToNumberBE(sk);
  if (x <= 0n || x >= CURVE_ORDER) {
    throw new Error('secret key must be in range (0, n)');
  }
  const y = Point.BASE.multiply(x);
  const { h } = encodeToCurve(y, alpha);
  const gamma = h.multiply(x);
  const k = nonceGenerationRFC6979(sk, h);
  const u = Point.BASE.multiply(k);
  const v = h.multiply(k);
  const c = challengeGeneration(y, h, gamma, u, v);
  const s = (k + c * x) % CURVE_ORDER;
  return encodeProof(gamma, c, s);
}

/**
 * RFC 9381 Section 5.3 — verify a VRF proof.
 *
 * @param pkBytes - 33-byte compressed public key
 * @param pi - 81-byte proof
 * @param alpha - arbitrary-length alpha string
 * @returns { valid, beta } where beta is the 32-byte VRF output if valid
 */
export function verify(
  pkBytes: Uint8Array,
  pi: Uint8Array,
  alpha: Uint8Array,
): { valid: boolean; beta: Uint8Array | null } {
  try {
    const { gamma, c, s } = decodeProof(pi);

    if (gamma.equals(Point.ZERO)) {
      return { valid: false, beta: null };
    }
    if (s >= CURVE_ORDER) {
      return { valid: false, beta: null };
    }
    if (c >= 1n << 128n) {
      return { valid: false, beta: null };
    }

    const y = bytesToPoint(pkBytes);
    const { h } = encodeToCurve(y, alpha);

    // U = s*G - c*Y  computed as  s*G + (n-c)*Y
    const u = Point.BASE.multiply(s).add(y.multiply(CURVE_ORDER - c));
    // V = s*H - c*Gamma  computed as  s*H + (n-c)*Gamma
    const v = h.multiply(s).add(gamma.multiply(CURVE_ORDER - c));

    const cPrime = challengeGeneration(y, h, gamma, u, v);

    if (c === cPrime) {
      const beta = proofToHash(pi);
      return { valid: true, beta };
    }
    return { valid: false, beta: null };
  } catch {
    return { valid: false, beta: null };
  }
}

/**
 * Derive the public key from a secret key.
 *
 * @param sk - 32-byte secret key
 * @returns 33-byte compressed public key
 */
export function getPublicKey(sk: Uint8Array): Uint8Array {
  const x = bytesToNumberBE(sk);
  if (x <= 0n || x >= CURVE_ORDER) {
    throw new Error('secret key must be in range (0, n)');
  }
  return pointToBytes(Point.BASE.multiply(x));
}
