/// RFC 9381 ECVRF-SECP256K1-SHA256-TAI.
///
/// Implements the final RFC 9381 standard, not draft-05/06. Suite byte 0xFE
/// (community convention for secp256k1).
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'secp256k1.dart';

const int _suiteByte = 0xfe;

/// Length in bytes of a proof: Gamma (33) || c (16) || s (32).
const int proofLength = 81;

/// Length in bytes of the VRF output beta.
const int betaLength = 32;

/// Length in bytes of a secret key.
const int secretKeyLength = 32;

/// Length in bytes of a compressed public key.
const int publicKeyLength = 33;

const int _challengeLength = 16;

/// The result of [verify]: whether the proof is valid and, if so, beta.
final class VerifyResult {
  /// True if the proof is valid for the public key and alpha.
  final bool valid;

  /// The 32-byte VRF output when [valid]; null otherwise.
  final Uint8List? beta;

  const VerifyResult._(this.valid, this.beta);

  static const VerifyResult _invalid = VerifyResult._(false, null);
}

/// A decoded proof.
typedef DecodedProof = ({Point gamma, BigInt c, BigInt s});

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(sha256.convert(data).bytes);

Uint8List _hmacSha256(List<int> key, List<int> data) =>
    Uint8List.fromList(Hmac(sha256, key).convert(data).bytes);

Uint8List _concat(List<List<int>> parts) {
  final builder = BytesBuilder(copy: false);
  for (final part in parts) {
    builder.add(part);
  }
  return builder.takeBytes();
}

BigInt _parseSecretKey(Uint8List sk) {
  if (sk.length != secretKeyLength) {
    throw ArgumentError.value(
      sk.length,
      'sk',
      'secret key must be $secretKeyLength bytes',
    );
  }
  final x = bytesToBigInt(sk);
  if (x == BigInt.zero || x >= groupOrder) {
    throw ArgumentError('secret key must be in range (0, n)');
  }
  return x;
}

/// RFC 9381 Section 5.4.1.1: try_and_increment encode-to-curve.
///
/// Candidates are decompressed with the even y-coordinate (0x02 prefix).
/// Returns H and the counter value that produced it.
({Point h, int ctr}) encodeToCurve(Point y, Uint8List alpha) {
  final pkBytes = y.toCompressed();
  for (var ctr = 0; ctr < 256; ctr++) {
    final hash = _sha256(
      _concat([
        [_suiteByte, 0x01],
        pkBytes,
        alpha,
        [ctr, 0x00],
      ]),
    );
    final point = Point.fromCompressed(
      _concat([
        [0x02],
        hash,
      ]),
    );
    if (point != null) return (h: point, ctr: ctr);
  }
  throw StateError('encode_to_curve: no valid point found in 256 iterations');
}

/// RFC 9381 Section 5.4.2.1: deterministic nonce via RFC 6979 Section 3.2.
///
/// The RFC 6979 message is point_to_string(H), hashed with SHA-256 to h1.
BigInt nonceGeneration(Uint8List sk, Point h) {
  final h1 = bytesToBigInt(_sha256(h.toCompressed()));
  // bits2octets(h1): qlen == hlen == 256, so reduce once modulo n.
  final h1Octets = bigIntToBytes(h1 % groupOrder, 32);

  var v = Uint8List(32)..fillRange(0, 32, 0x01);
  var k = Uint8List(32);
  k = _hmacSha256(
    k,
    _concat([
      v,
      [0x00],
      sk,
      h1Octets,
    ]),
  );
  v = _hmacSha256(k, v);
  k = _hmacSha256(
    k,
    _concat([
      v,
      [0x01],
      sk,
      h1Octets,
    ]),
  );
  v = _hmacSha256(k, v);

  while (true) {
    v = _hmacSha256(k, v);
    final candidate = bytesToBigInt(v);
    if (candidate > BigInt.zero && candidate < groupOrder) return candidate;
    k = _hmacSha256(
      k,
      _concat([
        v,
        [0x00],
      ]),
    );
    v = _hmacSha256(k, v);
  }
}

/// RFC 9381 Section 5.4.3: challenge over the five points (Y, H, Gamma, U, V).
BigInt challengeGeneration(Point y, Point h, Point gamma, Point u, Point v) {
  final hash = _sha256(
    _concat([
      [_suiteByte, 0x02],
      y.toCompressed(),
      h.toCompressed(),
      gamma.toCompressed(),
      u.toCompressed(),
      v.toCompressed(),
      [0x00],
    ]),
  );
  return bytesToBigInt(hash.sublist(0, _challengeLength));
}

Uint8List _gammaToHash(Point gamma) => _sha256(
  _concat([
    [_suiteByte, 0x03],
    gamma.toCompressed(), // cofactor is 1
    [0x00],
  ]),
);

/// Decodes an 81-byte proof into (Gamma, c, s).
///
/// Throws [ArgumentError] if the length is wrong, Gamma is not a valid
/// compressed point, or s is not below the group order.
DecodedProof decodeProof(Uint8List pi) {
  if (pi.length != proofLength) {
    throw ArgumentError.value(
      pi.length,
      'pi',
      'proof must be $proofLength bytes',
    );
  }
  final gamma = Point.fromCompressed(pi.sublist(0, 33));
  if (gamma == null) {
    throw ArgumentError('proof Gamma is not a valid compressed point');
  }
  final c = bytesToBigInt(pi.sublist(33, 33 + _challengeLength));
  final s = bytesToBigInt(pi.sublist(33 + _challengeLength, proofLength));
  if (s >= groupOrder) {
    throw ArgumentError('proof s must be less than the group order');
  }
  return (gamma: gamma, c: c, s: s);
}

/// Derives the 33-byte compressed public key for a 32-byte secret key.
///
/// Throws [ArgumentError] unless [sk] is 32 bytes encoding a scalar in (0, n).
Uint8List derivePublicKey(Uint8List sk) {
  final x = _parseSecretKey(sk);
  return Point.generator.multiply(x).toCompressed();
}

/// RFC 9381 Section 5.1: generates an 81-byte proof Gamma || c || s.
///
/// Throws [ArgumentError] unless [sk] is 32 bytes encoding a scalar in (0, n).
Uint8List prove(Uint8List sk, Uint8List alpha) {
  final x = _parseSecretKey(sk);
  final y = Point.generator.multiply(x);
  final h = encodeToCurve(y, alpha).h;
  final gamma = h.multiply(x);
  final k = nonceGeneration(sk, h);
  final u = Point.generator.multiply(k);
  final v = h.multiply(k);
  final c = challengeGeneration(y, h, gamma, u, v);
  final s = (k + c * x) % groupOrder;
  return _concat([
    gamma.toCompressed(),
    bigIntToBytes(c, _challengeLength),
    bigIntToBytes(s, 32),
  ]);
}

/// RFC 9381 Section 5.3: verifies [pi] for the 33-byte compressed public key
/// [pk] and [alpha].
///
/// Never throws: any malformed input yields an invalid result.
VerifyResult verify(Uint8List pk, Uint8List pi, Uint8List alpha) {
  final DecodedProof proof;
  try {
    proof = decodeProof(pi);
  } on ArgumentError {
    return VerifyResult._invalid;
  }
  final (:gamma, :c, :s) = proof;

  final y = Point.fromCompressed(pk);
  if (y == null) return VerifyResult._invalid;

  final h = encodeToCurve(y, alpha).h;
  final negC = (groupOrder - c) % groupOrder;

  // U = s*G - c*Y, V = s*H - c*Gamma.
  final u = Point.generator.multiply(s) + y.multiply(negC);
  final v = h.multiply(s) + gamma.multiply(negC);
  // The identity has no encoding, so no challenge can be computed over it.
  if (u.isIdentity || v.isIdentity) return VerifyResult._invalid;

  final cPrime = challengeGeneration(y, h, gamma, u, v);
  if (c != cPrime) return VerifyResult._invalid;
  return VerifyResult._(true, _gammaToHash(gamma));
}

/// RFC 9381 Section 5.2: the 32-byte VRF output beta of a proof, without
/// verifying it.
///
/// Throws [ArgumentError] if [pi] cannot be decoded (see [decodeProof]).
Uint8List proofToHash(Uint8List pi) => _gammaToHash(decodeProof(pi).gamma);
