"""RFC 9381 ECVRF — ECVRF-P256-SHA256-TAI and ECVRF-SECP256K1-SHA256-TAI.

Reference oracle implementation for generating and validating ECVRF
test vectors. The secp256k1 suite uses community convention suite byte
0xFE; the P-256 suite uses 0x01 per RFC 9381 Section 5.5.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass

from ecdsa import NIST256p, SECP256k1
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.errors import MalformedPointError
from ecdsa.rfc6979 import generate_k


@dataclass(frozen=True, slots=True)
class ECVRFSuite:
    """VRF cipher suite parameters per RFC 9381."""

    curve: Curve
    suite_byte: bytes
    cofactor: int


P256_SHA256_TAI = ECVRFSuite(curve=NIST256p, suite_byte=b"\x01", cofactor=1)
SECP256K1_SHA256_TAI = ECVRFSuite(curve=SECP256k1, suite_byte=b"\xfe", cofactor=1)


def point_to_string(point: PointJacobi) -> bytes:
    """SEC1 compressed point encoding (33 bytes for 256-bit curves)."""
    return point.to_bytes("compressed")


def string_to_point(suite: ECVRFSuite, data: bytes) -> PointJacobi:
    """Decompress a SEC1 compressed point on the suite's curve."""
    return PointJacobi.from_bytes(
        suite.curve.curve,
        data,
        valid_encodings=("compressed",),
        order=suite.curve.order,
    )


def i2osp(value: int, length: int) -> bytes:
    """Integer to Octet String Primitive — big-endian encoding."""
    return value.to_bytes(length, byteorder="big")


def os2ip(data: bytes) -> int:
    """Octet String to Integer Primitive — big-endian decoding."""
    return int.from_bytes(data, byteorder="big")


def encode_to_curve_tai(
    suite: ECVRFSuite, pk_point: PointJacobi, alpha: bytes
) -> tuple[PointJacobi, int]:
    """RFC 9381 Section 5.4.1.1 — try_and_increment hash-to-curve.

    Returns (H_point, ctr) where ctr is the counter value that succeeded.
    """
    pk_bytes = point_to_string(pk_point)
    for ctr in range(256):
        hash_input = (
            suite.suite_byte
            + b"\x01"
            + pk_bytes
            + alpha
            + bytes([ctr])
            + b"\x00"
        )
        candidate = hashlib.sha256(hash_input).digest()
        try:
            point = PointJacobi.from_bytes(
                suite.curve.curve,
                b"\x02" + candidate,
                valid_encodings=("compressed",),
                order=suite.curve.order,
            )
        except (MalformedPointError, ValueError):
            continue
        if suite.cofactor > 1:
            point = suite.cofactor * point
        return point, ctr
    raise ValueError("encode_to_curve: no valid point found in 256 iterations")


def nonce_generation_rfc6979(
    suite: ECVRFSuite, sk: int, h_point: PointJacobi
) -> int:
    """RFC 9381 Section 5.4.2.1 — deterministic nonce via RFC 6979.

    Per the spec, the "message" for RFC 6979 is point_to_string(H).
    The ecdsa library's generate_k expects the already-hashed message
    (h1 = Hash(m)), so we hash point_to_string(H) with SHA-256 first.
    """
    h_string = point_to_string(h_point)
    h1 = hashlib.sha256(h_string).digest()
    return generate_k(suite.curve.order, sk, hashlib.sha256, h1)


def challenge_generation(
    suite: ECVRFSuite,
    y: PointJacobi,
    h: PointJacobi,
    gamma: PointJacobi,
    u: PointJacobi,
    v: PointJacobi,
) -> int:
    """RFC 9381 Section 5.4.3 — 5-point challenge generation.

    Includes Y (public key) per RFC 9381; draft-05/06 omitted Y.
    """
    hash_input = (
        suite.suite_byte
        + b"\x02"
        + point_to_string(y)
        + point_to_string(h)
        + point_to_string(gamma)
        + point_to_string(u)
        + point_to_string(v)
        + b"\x00"
    )
    c_string = hashlib.sha256(hash_input).digest()
    return os2ip(c_string[:16])


def proof_to_hash(suite: ECVRFSuite, gamma: PointJacobi) -> bytes:
    """RFC 9381 Section 5.2 — derive VRF output (beta) from Gamma."""
    cofactor_gamma = gamma if suite.cofactor == 1 else suite.cofactor * gamma
    hash_input = (
        suite.suite_byte
        + b"\x03"
        + point_to_string(cofactor_gamma)
        + b"\x00"
    )
    return hashlib.sha256(hash_input).digest()


def decode_proof(suite: ECVRFSuite, pi: bytes) -> tuple[PointJacobi, int, int]:
    """Decode an 81-byte proof into (Gamma, c, s)."""
    if len(pi) != 81:
        raise ValueError(f"proof must be 81 bytes, got {len(pi)}")
    gamma = string_to_point(suite, pi[:33])
    c = os2ip(pi[33:49])
    s = os2ip(pi[49:81])
    return gamma, c, s


def ecvrf_prove(suite: ECVRFSuite, sk: bytes, alpha: bytes) -> bytes:
    """RFC 9381 Section 5.1 — generate a VRF proof.

    Returns pi (81 bytes): Gamma(33) || c(16) || s(32).
    """
    x = os2ip(sk)
    y = x * suite.curve.generator
    h, _ = encode_to_curve_tai(suite, y, alpha)
    gamma = x * h
    k = nonce_generation_rfc6979(suite, x, h)
    u = k * suite.curve.generator
    v = k * h
    c = challenge_generation(suite, y, h, gamma, u, v)
    s = (k + c * x) % suite.curve.order
    return point_to_string(gamma) + i2osp(c, 16) + i2osp(s, 32)


def ecvrf_verify(
    suite: ECVRFSuite, pk_bytes: bytes, pi: bytes, alpha: bytes
) -> tuple[bool, bytes | None]:
    """RFC 9381 Section 5.3 — verify a VRF proof.

    Returns (valid, beta) where beta is the VRF output if valid.
    """
    try:
        gamma, c, s = decode_proof(suite, pi)
    except (ValueError, MalformedPointError):
        return False, None

    if s >= suite.curve.order:
        return False, None
    if c >= (1 << 128):
        return False, None

    y = string_to_point(suite, pk_bytes)
    h, _ = encode_to_curve_tai(suite, y, alpha)

    # U = s*G - c*Y  computed as  s*G + (n-c)*Y
    n = suite.curve.order
    u = s * suite.curve.generator + (n - c) * y
    # V = s*H - c*Gamma  computed as  s*H + (n-c)*Gamma
    v = s * h + (n - c) * gamma

    c_prime = challenge_generation(suite, y, h, gamma, u, v)

    if c == c_prime:
        beta = proof_to_hash(suite, gamma)
        return True, beta
    return False, None


def ecvrf_proof_to_hash(suite: ECVRFSuite, pi: bytes) -> bytes:
    """Extract VRF output (beta) from an already-validated proof."""
    gamma, _, _ = decode_proof(suite, pi)
    return proof_to_hash(suite, gamma)


# ---------------------------------------------------------------------------
# P-256 self-validation against RFC 9381 Appendix A test vectors
# ---------------------------------------------------------------------------

_P256_VECTORS = [
    {
        "name": "Example 10 (alpha='sample')",
        "sk": "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "pk": "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "alpha": "73616d706c65",
        "h": "0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4",
        "k": "0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77",
        "u": "02bb6a034f67643c6183c10f8b41dc4babf88bff154b674e377d90bde009c21672",
        "v": "02893ebee7af9a0faa6da810da8a91f9d50e1dc071240c9706726820ff919e8394",
        "pi": "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4"
              "a53f0a46f018bc2c56e58d383f2305e0"
              "975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f",
        "beta": "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
    },
    {
        "name": "Example 11 (alpha='test')",
        "sk": "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "pk": "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "alpha": "74657374",
        "h": "02173119b4fff5e6f8afed4868a29fe8920f1b54c2cf89cc7b301d0d473de6b974",
        "k": "5852353a868bdce26938cde1826723e58bf8cb06dd2fed475213ea6f3b12e961",
        "u": "022779a2cafcb65414c4a04a4b4d2adf4c50395f57995e89e6de823250d91bc48e",
        "v": "033b4a14731672e82339f03b45ff6b5b13dee7ada38c9bf1d6f8f61e2ce5921119",
        "pi": "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56"
              "c19e067b15a8a8174905b13617804534"
              "214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854",
        "beta": "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
    },
    {
        "name": "Example 12 (different key)",
        "sk": "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8",
        "pk": "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
        "alpha": "4578616d706c65207573696e67204543445341206b65792066726f6d"
                 "20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035",
        "h": "0258055c26c4b01d01c00fb57567955f7d39cd6f6e85fd37c58f696cc6b7aa761d",
        "k": "5689e2e08e1110b4dda293ac21667eac6db5de4a46a519c73d533f69be2f4da3",
        "u": "020f465cd0ec74d2e23af0abde4c07e866ae4e5138bded5dd1196b8843f380db84",
        "v": "036cb6f811428fc4904370b86c488f60c280fa5b496d2f34ff8772f60ed24b2d1d",
        "pi": "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667"
              "d091c00b0f5c3619d10ecea44363b5a5"
              "99cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1",
        "beta": "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19",
    },
]


def _check_intermediate(
    label: str, got: str, expected: str, errors: list[str]
) -> None:
    if got != expected:
        errors.append(f"    {label}: MISMATCH")
        errors.append(f"      expected: {expected}")
        errors.append(f"      got:      {got}")


def validate_p256_vectors() -> bool:
    """Validate the oracle against RFC 9381 P-256 test vectors.

    Returns True if all vectors pass byte-identical checks.
    """
    suite = P256_SHA256_TAI
    passed = 0
    failed = 0

    for vec in _P256_VECTORS:
        sk = bytes.fromhex(vec["sk"])
        alpha = bytes.fromhex(vec["alpha"])
        expected_pi = vec["pi"]
        expected_beta = vec["beta"]
        errors: list[str] = []

        # Verify SK → PK derivation
        x = os2ip(sk)
        y_point = x * suite.curve.generator
        pk_hex = point_to_string(y_point).hex()
        _check_intermediate("PK", pk_hex, vec["pk"], errors)

        # Check encode_to_curve
        h_point, h_ctr = encode_to_curve_tai(suite, y_point, alpha)
        h_hex = point_to_string(h_point).hex()
        _check_intermediate("H", h_hex, vec["h"], errors)

        # Check nonce generation
        k = nonce_generation_rfc6979(suite, x, h_point)
        k_hex = format(k, "064x")
        _check_intermediate("k", k_hex, vec["k"], errors)

        # Check intermediate points
        u_point = k * suite.curve.generator
        v_point = k * h_point
        _check_intermediate("U", point_to_string(u_point).hex(), vec["u"], errors)
        _check_intermediate("V", point_to_string(v_point).hex(), vec["v"], errors)

        # Full prove
        pi = ecvrf_prove(suite, sk, alpha)
        pi_hex = pi.hex()
        beta = ecvrf_proof_to_hash(suite, pi)
        beta_hex = beta.hex()

        _check_intermediate("pi", pi_hex, expected_pi, errors)
        _check_intermediate("beta", beta_hex, expected_beta, errors)

        # Verify round-trip
        pk_bytes = bytes.fromhex(vec["pk"])
        valid, verify_beta = ecvrf_verify(suite, pk_bytes, pi, alpha)
        if not valid:
            errors.append("    verify: returned INVALID on own proof")
        elif verify_beta is not None and verify_beta.hex() != expected_beta:
            errors.append("    verify beta mismatch")

        if errors:
            print(f"  {vec['name']}: FAIL")
            for e in errors:
                print(e)
            failed += 1
        else:
            print(f"  {vec['name']}: PASS")
            passed += 1

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    print("RFC 9381 ECVRF-P256-SHA256-TAI — Self-Validation")
    print("=" * 52)
    success = validate_p256_vectors()
    if success:
        print("\nAll P-256 vectors match. Oracle algorithm is correct.")
    else:
        print("\nP-256 validation FAILED. Do NOT trust secp256k1 output.")
    sys.exit(0 if success else 1)
