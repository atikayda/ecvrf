/// secp256k1 group arithmetic over Dart's [BigInt].
///
/// Hand-rolled so the package needs no third-party elliptic-curve library.
/// None of this is constant-time: [BigInt] operations take time that depends
/// on the values involved. See SECURITY.md.
library;

import 'dart:typed_data';

/// Field prime p = 2^256 - 2^32 - 977.
final BigInt fieldPrime = BigInt.parse(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  radix: 16,
);

/// Group order n.
final BigInt groupOrder = BigInt.parse(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  radix: 16,
);

final BigInt _seven = BigInt.from(7);

/// (p + 1) / 4, the exponent for square roots since p = 3 (mod 4).
final BigInt _sqrtExponent = (fieldPrime + BigInt.one) >> 2;

/// A point on secp256k1 in affine coordinates, or the point at infinity.
final class Point {
  /// Affine x-coordinate; meaningless for the identity.
  final BigInt x;

  /// Affine y-coordinate; meaningless for the identity.
  final BigInt y;

  /// Whether this is the point at infinity (the group identity).
  final bool isIdentity;

  const Point._(this.x, this.y, this.isIdentity);

  /// The point at infinity.
  static final Point identity = Point._(BigInt.zero, BigInt.zero, true);

  /// The standard generator G.
  static final Point generator = Point._(
    BigInt.parse(
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      radix: 16,
    ),
    BigInt.parse(
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      radix: 16,
    ),
    false,
  );

  /// Decodes a 33-byte SEC1 compressed point (prefix 0x02 or 0x03).
  ///
  /// Returns null if the input is not exactly 33 bytes, the prefix is not
  /// 0x02/0x03, x is not below p, or x^3 + 7 has no square root mod p.
  /// The identity has no compressed encoding and so is never returned.
  static Point? fromCompressed(Uint8List data) {
    if (data.length != 33) return null;
    final prefix = data[0];
    if (prefix != 0x02 && prefix != 0x03) return null;
    final x = bytesToBigInt(data.sublist(1));
    if (x >= fieldPrime) return null;
    final rhs = (x * x % fieldPrime * x + _seven) % fieldPrime;
    var y = rhs.modPow(_sqrtExponent, fieldPrime);
    if (y * y % fieldPrime != rhs) return null;
    if (y.isOdd != (prefix == 0x03)) y = fieldPrime - y;
    // y == 0 cannot occur on secp256k1 (x^3 = -7 has no solution mod p).
    return Point._(x, y, false);
  }

  /// SEC1 compressed encoding (33 bytes). The identity cannot be encoded.
  Uint8List toCompressed() {
    if (isIdentity) {
      throw StateError('the point at infinity has no compressed encoding');
    }
    final out = Uint8List(33);
    out[0] = y.isOdd ? 0x03 : 0x02;
    out.setRange(1, 33, bigIntToBytes(x, 32));
    return out;
  }

  /// Group addition.
  Point operator +(Point other) =>
      _Jacobian.fromAffine(this).add(_Jacobian.fromAffine(other)).toAffine();

  /// The additive inverse.
  Point operator -() =>
      isIdentity ? this : Point._(x, (fieldPrime - y) % fieldPrime, false);

  /// Scalar multiplication k * this, for any non-negative k.
  Point multiply(BigInt k) {
    final scalar = k % groupOrder;
    var acc = _Jacobian.infinity;
    final base = _Jacobian.fromAffine(this);
    for (var i = scalar.bitLength - 1; i >= 0; i--) {
      acc = acc.double();
      if ((scalar >> i).isOdd) acc = acc.add(base);
    }
    return acc.toAffine();
  }

  @override
  bool operator ==(Object other) =>
      other is Point &&
      (isIdentity
          ? other.isIdentity
          : !other.isIdentity && x == other.x && y == other.y);

  @override
  int get hashCode => isIdentity ? 0 : Object.hash(x, y);
}

/// Jacobian coordinates (X, Y, Z) representing (X/Z^2, Y/Z^3); Z = 0 is the
/// identity. Used inside scalar multiplication to avoid an inversion per step.
final class _Jacobian {
  final BigInt x;
  final BigInt y;
  final BigInt z;

  const _Jacobian(this.x, this.y, this.z);

  static final _Jacobian infinity = _Jacobian(
    BigInt.one,
    BigInt.one,
    BigInt.zero,
  );

  static _Jacobian fromAffine(Point p) =>
      p.isIdentity ? infinity : _Jacobian(p.x, p.y, BigInt.one);

  bool get isInfinity => z == BigInt.zero;

  Point toAffine() {
    if (isInfinity) return Point.identity;
    final zInv = z.modInverse(fieldPrime);
    final zInv2 = zInv * zInv % fieldPrime;
    final zInv3 = zInv2 * zInv % fieldPrime;
    return Point._(x * zInv2 % fieldPrime, y * zInv3 % fieldPrime, false);
  }

  // dbl-2009-l (a = 0).
  _Jacobian double() {
    if (isInfinity || y == BigInt.zero) return infinity;
    final p = fieldPrime;
    final a = x * x % p;
    final b = y * y % p;
    final c = b * b % p;
    final xb = (x + b) % p;
    final d = (BigInt.two * ((xb * xb - a - c) % p)) % p;
    final e = BigInt.from(3) * a % p;
    final f = e * e % p;
    final x3 = (f - BigInt.two * d) % p;
    final y3 = (e * ((d - x3) % p) - BigInt.from(8) * c) % p;
    final z3 = BigInt.two * y * z % p;
    return _Jacobian(x3, y3, z3);
  }

  // add-2007-bl, with the doubling and inverse cases handled explicitly.
  _Jacobian add(_Jacobian o) {
    if (isInfinity) return o;
    if (o.isInfinity) return this;
    final p = fieldPrime;
    final z1z1 = z * z % p;
    final z2z2 = o.z * o.z % p;
    final u1 = x * z2z2 % p;
    final u2 = o.x * z1z1 % p;
    final s1 = y * o.z % p * z2z2 % p;
    final s2 = o.y * z % p * z1z1 % p;
    final h = (u2 - u1) % p;
    final r = (s2 - s1) % p;
    if (h == BigInt.zero) {
      return r == BigInt.zero ? double() : infinity;
    }
    final hh = h * h % p;
    final hhh = h * hh % p;
    final v = u1 * hh % p;
    final x3 = (r * r - hhh - BigInt.two * v) % p;
    final y3 = (r * ((v - x3) % p) - s1 * hhh) % p;
    final z3 = z * o.z % p * h % p;
    return _Jacobian(x3, y3, z3);
  }
}

/// OS2IP: big-endian bytes to a non-negative integer.
BigInt bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// I2OSP: a non-negative integer below 256^[length] to big-endian bytes.
Uint8List bigIntToBytes(BigInt value, int length) {
  if (value.isNegative || value.bitLength > length * 8) {
    throw ArgumentError.value(value, 'value', 'does not fit in $length bytes');
  }
  final out = Uint8List(length);
  final mask = BigInt.from(0xff);
  var v = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}
