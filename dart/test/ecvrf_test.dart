import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ecvrf/ecvrf.dart';
import 'package:ecvrf/src/ecvrf.dart'
    show challengeGeneration, decodeProof, encodeToCurve, nonceGeneration;
import 'package:ecvrf/src/secp256k1.dart';
import 'package:test/test.dart';

Uint8List fromHex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Map<String, Object?> _loadVectors() {
  // `dart test` runs from the package root, so the shared vectors are at
  // ../vectors/vectors.json, the same path the other implementations use.
  final file = File('../vectors/vectors.json');
  return jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
}

void main() {
  final data = _loadVectors();
  final vectors = (data['vectors']! as List<Object?>)
      .cast<Map<String, Object?>>();
  final negativeVectors = (data['negative_vectors']! as List<Object?>)
      .cast<Map<String, Object?>>();

  test('vector file shape', () {
    expect(data['suite'], 'ECVRF-SECP256K1-SHA256-TAI');
    expect(data['spec'], 'RFC 9381');
    expect(vectors, isNotEmpty);
    expect(negativeVectors, isNotEmpty);
  });

  group('positive vectors', () {
    for (final vec in vectors) {
      final label = vec['label']! as String;
      String field(String name) => vec[name]! as String;

      group(label, () {
        final sk = fromHex(field('sk'));
        final pk = fromHex(field('pk'));
        final alpha = fromHex(field('alpha'));
        final pi = fromHex(field('pi'));

        test('derivePublicKey', () {
          expect(toHex(derivePublicKey(sk)), field('pk'));
        });

        test('prove', () {
          expect(toHex(prove(sk, alpha)), field('pi'));
        });

        test('proofToHash', () {
          expect(toHex(proofToHash(pi)), field('beta'));
        });

        test('verify', () {
          final result = verify(pk, pi, alpha);
          expect(result.valid, isTrue);
          expect(toHex(result.beta!), field('beta'));
        });

        test('intermediate values', () {
          final x = bytesToBigInt(sk);
          final y = Point.generator.multiply(x);
          expect(toHex(y.toCompressed()), field('pk'));

          final (:h, :ctr) = encodeToCurve(y, alpha);
          expect(toHex(h.toCompressed()), field('h'));
          expect(ctr, vec['h_ctr']);

          final k = nonceGeneration(sk, h);
          expect(toHex(bigIntToBytes(k, 32)), field('k'));

          final gamma = h.multiply(x);
          expect(toHex(gamma.toCompressed()), field('gamma'));

          final u = Point.generator.multiply(k);
          final v = h.multiply(k);
          expect(toHex(u.toCompressed()), field('u'));
          expect(toHex(v.toCompressed()), field('v'));

          final c = challengeGeneration(y, h, gamma, u, v);
          expect(toHex(bigIntToBytes(c, 16)), field('c'));
          final s = (k + c * x) % groupOrder;
          expect(toHex(bigIntToBytes(s, 32)), field('s'));

          final decoded = decodeProof(pi);
          expect(decoded.gamma, gamma);
          expect(decoded.c, c);
          expect(decoded.s, s);
          expect(field('pi'), field('gamma') + field('c') + field('s'));
        });

        test('determinism', () {
          expect(toHex(prove(sk, alpha)), toHex(prove(sk, alpha)));
        });

        test('round-trip', () {
          final ownPi = prove(sk, alpha);
          final ownPk = derivePublicKey(sk);
          final result = verify(ownPk, ownPi, alpha);
          expect(result.valid, isTrue);
          expect(toHex(result.beta!), toHex(proofToHash(ownPi)));
          expect(toHex(result.beta!), field('beta'));
        });
      });
    }
  });

  group('negative vectors', () {
    for (final vec in negativeVectors) {
      final description = vec['description']! as String;
      test('reject: $description', () {
        final result = verify(
          fromHex(vec['pk']! as String),
          fromHex(vec['pi']! as String),
          fromHex(vec['alpha']! as String),
        );
        expect(result.valid, vec['expected_verify']);
        expect(result.valid, isFalse);
        expect(result.beta, isNull);
      });
    }
  });

  group('invalid secret key rejection', () {
    final n = bigIntToBytes(groupOrder, 32);
    final alpha = Uint8List.fromList(utf8.encode('test'));
    final cases = <String, Uint8List>{
      'zero key': Uint8List(32),
      'sk = n (group order)': n,
      'sk = n + 1': bigIntToBytes(groupOrder + BigInt.one, 32),
      'sk = 2^256 - 1': Uint8List(32)..fillRange(0, 32, 0xff),
      'too short (31 bytes)': Uint8List(31)..[30] = 1,
      'too long (33 bytes)': Uint8List(33)..[32] = 1,
      'empty': Uint8List(0),
    };
    cases.forEach((name, sk) {
      test('prove rejects $name', () {
        expect(() => prove(sk, alpha), throwsArgumentError);
      });
      test('derivePublicKey rejects $name', () {
        expect(() => derivePublicKey(sk), throwsArgumentError);
      });
    });
  });

  group('malformed input handling', () {
    final vec = vectors.first;
    final pk = fromHex(vec['pk']! as String);
    final pi = fromHex(vec['pi']! as String);
    final alpha = fromHex(vec['alpha']! as String);

    test('proofToHash rejects wrong lengths', () {
      expect(() => proofToHash(pi.sublist(0, 80)), throwsArgumentError);
      expect(
        () => proofToHash(Uint8List.fromList([...pi, 0])),
        throwsArgumentError,
      );
      expect(() => proofToHash(Uint8List(0)), throwsArgumentError);
    });

    test('proofToHash rejects an undecodable Gamma', () {
      expect(() => proofToHash(Uint8List(proofLength)), throwsArgumentError);
    });

    test('verify rejects an uncompressed public key', () {
      final y = Point.fromCompressed(pk)!;
      final uncompressed = Uint8List.fromList([
        0x04,
        ...bigIntToBytes(y.x, 32),
        ...bigIntToBytes(y.y, 32),
      ]);
      expect(verify(uncompressed, pi, alpha).valid, isFalse);
    });

    test('verify rejects a public key with the wrong parity prefix', () {
      final flipped = Uint8List.fromList(pk)..[0] ^= 0x01;
      expect(verify(flipped, pi, alpha).valid, isFalse);
    });

    test('verify rejects a public key with x >= p', () {
      final bad = Uint8List.fromList([0x02, ...bigIntToBytes(fieldPrime, 32)]);
      expect(verify(bad, pi, alpha).valid, isFalse);
    });

    test('verify rejects empty and truncated public keys', () {
      expect(verify(Uint8List(0), pi, alpha).valid, isFalse);
      expect(verify(pk.sublist(0, 32), pi, alpha).valid, isFalse);
    });
  });
}
