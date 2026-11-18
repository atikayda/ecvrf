/// RFC 9381 ECVRF-SECP256K1-SHA256-TAI (Verifiable Random Function) in pure
/// Dart.
///
/// ```dart
/// final pk = derivePublicKey(sk);       // 33 bytes, compressed
/// final pi = prove(sk, alpha);          // 81 bytes
/// final result = verify(pk, pi, alpha); // result.valid, result.beta
/// ```
///
/// Not constant-time; see SECURITY.md in the repository.
library;

export 'src/ecvrf.dart'
    show
        VerifyResult,
        betaLength,
        derivePublicKey,
        proofLength,
        proofToHash,
        prove,
        publicKeyLength,
        secretKeyLength,
        verify;
