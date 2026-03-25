#!/usr/bin/env python3
"""CLI wrapper for ECVRF Python implementation — cross-validation use only."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
from ecvrf import (
    SECP256K1_SHA256_TAI as SUITE,
    ecvrf_prove,
    ecvrf_proof_to_hash,
    ecvrf_verify,
)


def read_alpha(args: list, idx: int) -> str:
    """Read alpha hex from --alpha-file flag or positional argument."""
    if args[idx] == "--alpha-file":
        return Path(args[idx + 1]).read_text().strip()
    return args[idx]


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python-cli.py prove|verify ...", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "prove":
        sk_hex = sys.argv[2]
        alpha_hex = read_alpha(sys.argv, 3)
        pi = ecvrf_prove(SUITE, bytes.fromhex(sk_hex), bytes.fromhex(alpha_hex))
        beta = ecvrf_proof_to_hash(SUITE, pi)
        print(json.dumps({"pi": pi.hex(), "beta": beta.hex()}))

    elif cmd == "verify":
        pk_hex, pi_hex = sys.argv[2], sys.argv[3]
        alpha_hex = read_alpha(sys.argv, 4)
        valid, beta = ecvrf_verify(
            SUITE,
            bytes.fromhex(pk_hex),
            bytes.fromhex(pi_hex),
            bytes.fromhex(alpha_hex),
        )
        result = {"valid": valid, "beta": beta.hex() if beta else None}
        print(json.dumps(result))

    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
