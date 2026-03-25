"""Generate ECVRF-SECP256K1-SHA256-TAI test vectors per RFC 9381.

Produces vectors/vectors.json with 50+ positive vectors and 15+ negative
vectors, covering all categories specified in the project plan.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ecvrf import (
    SECP256K1_SHA256_TAI as SUITE,
    ecvrf_prove,
    ecvrf_verify,
    ecvrf_proof_to_hash,
    encode_to_curve_tai,
    nonce_generation_rfc6979,
    challenge_generation,
    point_to_string,
    os2ip,
    i2osp,
)
from ecdsa import SECP256k1

ORDER = SECP256k1.order
VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors"


def _derive_sk(seed: str) -> bytes:
    """Deterministic secret key from a seed string."""
    raw = hashlib.sha256(seed.encode()).digest()
    scalar = os2ip(raw) % (ORDER - 1) + 1
    return i2osp(scalar, 32)


def _make_vector(sk: bytes, alpha: bytes, *, label: str) -> dict:
    """Generate one positive vector with all intermediate values."""
    x = os2ip(sk)
    y = x * SUITE.curve.generator
    pk_bytes = point_to_string(y)

    h_point, h_ctr = encode_to_curve_tai(SUITE, y, alpha)
    k = nonce_generation_rfc6979(SUITE, x, h_point)
    gamma = x * h_point
    u = k * SUITE.curve.generator
    v = k * h_point
    c = challenge_generation(SUITE, y, h_point, gamma, u, v)
    s_val = (k + c * x) % ORDER

    pi = ecvrf_prove(SUITE, sk, alpha)
    beta = ecvrf_proof_to_hash(SUITE, pi)

    valid, vbeta = ecvrf_verify(SUITE, pk_bytes, pi, alpha)
    assert valid, f"self-verify failed: {label}"
    assert vbeta == beta, f"beta mismatch: {label}"

    try:
        alpha_str: str | None = alpha.decode("utf-8")
    except UnicodeDecodeError:
        alpha_str = None

    return {
        "label": label,
        "sk": sk.hex(),
        "pk": pk_bytes.hex(),
        "alpha": alpha.hex(),
        "alpha_string": alpha_str,
        "h": point_to_string(h_point).hex(),
        "h_ctr": h_ctr,
        "k": format(k, "064x"),
        "gamma": point_to_string(gamma).hex(),
        "u": point_to_string(u).hex(),
        "v": point_to_string(v).hex(),
        "c": format(c, "032x"),
        "s": format(s_val, "064x"),
        "pi": pi.hex(),
        "beta": beta.hex(),
    }


def _find_high_ctr_alpha(sk: bytes, min_ctr: int) -> bytes:
    """Search for an alpha where try_and_increment needs ctr > min_ctr."""
    x = os2ip(sk)
    y = x * SUITE.curve.generator
    for i in range(200_000):
        alpha = f"highctr-{i:06d}".encode()
        _, ctr = encode_to_curve_tai(SUITE, y, alpha)
        if ctr > min_ctr:
            return alpha
    raise ValueError(f"no alpha found with ctr > {min_ctr}")


def _generate_positive_vectors() -> list[dict]:
    sk_min = i2osp(1, 32)
    sk_2 = i2osp(2, 32)
    sk_max = i2osp(ORDER - 1, 32)
    sk_max2 = i2osp(ORDER - 2, 32)
    sk_mid = i2osp(ORDER // 2, 32)
    sk_a = _derive_sk("ecvrf-test-key-1")
    sk_b = _derive_sk("ecvrf-test-key-2")
    sk_c = _derive_sk("ecvrf-test-key-3")

    cases: list[tuple[bytes, bytes, str]] = []

    # --- Empty alpha ---
    cases.append((sk_min, b"", "empty alpha, sk=1"))
    cases.append((sk_a, b"", "empty alpha, key A"))
    cases.append((sk_b, b"", "empty alpha, key B"))

    # --- Single byte alphas ---
    cases.append((sk_a, b"\x00", "single null byte, key A"))
    cases.append((sk_min, b"\x00", "single null byte, sk=1"))
    cases.append((sk_a, b"A", "single byte 0x41, key A"))
    cases.append((sk_a, b"\xff", "single byte 0xff, key A"))

    # --- Short alpha: game format, sequential (same key) ---
    for i in range(1, 11):
        cases.append((sk_a, f"01-{i:06d}".encode(), f"game seq 01-{i:06d}, key A"))

    # --- Medium alpha: roll format ---
    cases.append((sk_a, b"01-000001-000012", "roll format, key A"))
    cases.append((sk_a, b"01-000005-000042", "roll format 2, key A"))

    # --- Cross-key: same alpha, different keys ---
    cases.append((sk_b, b"01-000001", "game 01-000001, key B"))
    cases.append((sk_c, b"01-000001", "game 01-000001, key C"))
    cases.append((sk_min, b"01-000001", "game 01-000001, sk=1"))

    # --- Common string alphas ---
    cases.append((sk_a, b"sample", "alpha='sample', key A"))
    cases.append((sk_a, b"test", "alpha='test', key A"))
    cases.append((sk_b, b"sample", "alpha='sample', key B"))
    cases.append((sk_c, b"sample", "alpha='sample', key C"))
    cases.append((sk_min, b"sample", "alpha='sample', sk=1"))
    cases.append((sk_min, b"test", "alpha='test', sk=1"))
    cases.append((sk_b, b"test", "alpha='test', key B"))
    cases.append((sk_c, b"test", "alpha='test', key C"))

    # --- Edge case keys ---
    cases.append((sk_max, b"", "empty alpha, sk=n-1"))
    cases.append((sk_max, b"sample", "alpha='sample', sk=n-1"))
    cases.append((sk_max, b"01-000001", "game format, sk=n-1"))
    cases.append((sk_mid, b"", "empty alpha, sk=n/2"))
    cases.append((sk_mid, b"sample", "alpha='sample', sk=n/2"))
    cases.append((sk_mid, b"01-000001", "game format, sk=n/2"))
    cases.append((sk_2, b"sample", "alpha='sample', sk=2"))
    cases.append((sk_max2, b"sample", "alpha='sample', sk=n-2"))

    # --- Long alpha (256 bytes) ---
    cases.append((sk_a, b"L" * 256, "256-byte alpha, key A"))

    # --- Very long alpha (64KB+) ---
    cases.append((sk_a, b"X" * (64 * 1024 + 1), "64KB+1 alpha, key A"))

    # --- Binary non-UTF-8 ---
    cases.append((sk_a, bytes([0x80, 0x81, 0xfe, 0xff]), "binary non-utf8 4 bytes"))
    cases.append((sk_a, bytes(range(128, 160)), "binary range 0x80-0x9f"))

    # --- Embedded null bytes ---
    cases.append((sk_a, b"hello\x00world", "embedded null in ascii"))
    cases.append((sk_a, b"\x00\x00\x00", "triple null bytes"))

    # --- Misc ---
    cases.append((sk_a, b"02-000001", "game prefix 02"))
    cases.append((sk_a, b"99-999999", "max game numbers"))
    cases.append((sk_a, b"\x01\x02\x03\x04\x05\x06\x07\x08", "sequential bytes 1-8"))

    # --- Additional coverage ---
    cases.append((sk_a, b" ", "single space, key A"))
    cases.append((sk_min, b"L" * 256, "256-byte alpha, sk=1"))
    cases.append((sk_a, "こんにちは".encode(), "utf-8 multibyte, key A"))

    # --- High ctr (>10) ---
    print("  Searching for high-ctr alpha (ctr > 10)...")
    high_ctr_alpha = _find_high_ctr_alpha(sk_a, 10)
    cases.append((sk_a, high_ctr_alpha, f"high ctr (>10), alpha='{high_ctr_alpha.decode()}'"))

    vectors = []
    for sk, alpha, label in cases:
        vec = _make_vector(sk, alpha, label=label)
        vectors.append(vec)
        pk_prefix = vec["pk"][:2]
        print(f"  [{len(vectors):2d}] ctr={vec['h_ctr']:2d}  pk=0x{pk_prefix}  {label}")

    return vectors


def _generate_negative_vectors(positive: list[dict]) -> list[dict]:
    """Generate negative vectors — proofs that MUST NOT verify."""
    base = positive[0]
    pk = base["pk"]
    alpha = base["alpha"]
    pi_bytes = bytes.fromhex(base["pi"])

    negatives: list[dict] = []

    # 1. Tampered Gamma — bit flip in x-coordinate
    bad = bytearray(pi_bytes)
    bad[5] ^= 0x01
    negatives.append({
        "description": "tampered Gamma (bit flip at byte 5)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 2. Tampered Gamma — flip high bit of x-coordinate
    bad = bytearray(pi_bytes)
    bad[1] ^= 0x80
    negatives.append({
        "description": "tampered Gamma (bit flip at byte 1)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 3. Tampered c — bit flip in challenge
    bad = bytearray(pi_bytes)
    bad[33] ^= 0x01
    negatives.append({
        "description": "tampered c (bit flip at byte 33)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 4. Tampered c — zeroed challenge
    bad = bytearray(pi_bytes)
    bad[33:49] = b"\x00" * 16
    negatives.append({
        "description": "tampered c (zeroed challenge)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 5. Tampered s — bit flip
    bad = bytearray(pi_bytes)
    bad[49] ^= 0x01
    negatives.append({
        "description": "tampered s (bit flip at byte 49)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 6. s = group order n (out of range)
    bad = bytearray(pi_bytes)
    bad[49:81] = i2osp(ORDER, 32)
    negatives.append({
        "description": "s >= group order (s = n)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 7. s = n + 1
    bad = bytearray(pi_bytes)
    bad[49:81] = i2osp(ORDER + 1, 32)
    negatives.append({
        "description": "s = n + 1",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 8. Wrong public key
    other_pk = positive[2]["pk"]
    negatives.append({
        "description": "valid proof verified with wrong public key",
        "pk": other_pk, "alpha": alpha,
        "pi": base["pi"], "expected_verify": False,
    })

    # 9. Wrong alpha
    negatives.append({
        "description": "valid proof verified with wrong alpha",
        "pk": pk, "alpha": "deadbeef",
        "pi": base["pi"], "expected_verify": False,
    })

    # 10. Truncated proof (80 bytes)
    negatives.append({
        "description": "truncated proof (80 bytes)",
        "pk": pk, "alpha": alpha,
        "pi": pi_bytes[:80].hex(), "expected_verify": False,
    })

    # 11. Extended proof (82 bytes with trailing junk)
    negatives.append({
        "description": "extended proof (82 bytes, trailing 0xff)",
        "pk": pk, "alpha": alpha,
        "pi": (pi_bytes + b"\xff").hex(), "expected_verify": False,
    })

    # 12. Gamma not on curve (x >= field prime)
    bad = bytearray(pi_bytes)
    bad[0:33] = b"\x02" + b"\xff" * 32
    negatives.append({
        "description": "Gamma not on curve (x = 2^256-1 > p)",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 13. All-zero proof
    negatives.append({
        "description": "all-zero proof (81 bytes of 0x00)",
        "pk": pk, "alpha": alpha,
        "pi": "00" * 81, "expected_verify": False,
    })

    # 14. Invalid SEC1 prefix on Gamma
    bad = bytearray(pi_bytes)
    bad[0] = 0x04
    negatives.append({
        "description": "Gamma with invalid SEC1 prefix 0x04",
        "pk": pk, "alpha": alpha,
        "pi": bytes(bad).hex(), "expected_verify": False,
    })

    # 15. Empty-vs-null confusion (proof for "" verified with "\x00")
    negatives.append({
        "description": "empty alpha proof verified with single null byte alpha",
        "pk": pk, "alpha": "00",
        "pi": base["pi"], "expected_verify": False,
    })

    for neg in negatives:
        pk_b = bytes.fromhex(neg["pk"])
        pi_b = bytes.fromhex(neg["pi"])
        alpha_b = bytes.fromhex(neg["alpha"])
        valid, _ = ecvrf_verify(SUITE, pk_b, pi_b, alpha_b)
        assert not valid, f"negative vector should fail: {neg['description']}"

    return negatives


def main() -> None:
    print("Generating ECVRF-SECP256K1-SHA256-TAI test vectors\n")

    print("Positive vectors:")
    positive = _generate_positive_vectors()
    print(f"\n  Total: {len(positive)} positive vectors")

    # Verify we have both PK prefix parities
    prefixes = {v["pk"][:2] for v in positive}
    print(f"  PK prefix parities: {sorted(prefixes)}")

    # Count ctr=0 and high-ctr vectors
    ctr_0 = sum(1 for v in positive if v["h_ctr"] == 0)
    ctr_high = sum(1 for v in positive if v["h_ctr"] > 10)
    print(f"  Vectors with ctr=0: {ctr_0}")
    print(f"  Vectors with ctr>10: {ctr_high}")

    print("\nNegative vectors:")
    negative = _generate_negative_vectors(positive)
    for i, neg in enumerate(negative, 1):
        print(f"  [{i:2d}] {neg['description']}")
    print(f"\n  Total: {len(negative)} negative vectors")

    output = {
        "suite": "ECVRF-SECP256K1-SHA256-TAI",
        "spec": "RFC 9381",
        "vectors": positive,
        "negative_vectors": negative,
    }

    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = VECTORS_DIR / "vectors.json"
    out_path.write_text(json.dumps(output, indent=2) + "\n")
    print(f"\nWritten to {out_path}")
    print(f"File size: {out_path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
