![CI](https://github.com/atikayda/ecvrf/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg) ![RFC 9381](https://img.shields.io/badge/RFC-9381-green.svg)

# ECVRF-SECP256K1-SHA256-TAI - RFC 9381

Cross-checked reference implementations of ECVRF-SECP256K1-SHA256-TAI as specified by [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381). Four independent implementations (Python, Go, Rust, TypeScript) validated against a shared set of test vectors.

## The Problem

RFC 9381 is the ratified IETF standard for Verifiable Random Functions, superseding earlier drafts (draft-05, draft-06). Every existing secp256k1 VRF implementation in the wild follows one of those drafts. None follow the final standard.

The differences are not cosmetic - they are security-relevant:

| Area | Draft-05/06 | RFC 9381 |
|---|---|---|
| `challenge_generation` input | 4 points: `H, Gamma, U, V` | 5 points: `Y, H, Gamma, U, V` (adds public key) |
| Domain separators | No trailing separators | `0x01`, `0x02`, `0x03` prefixes + trailing `0x00` on all hash operations |
| `proof_to_hash` | No trailing byte | Trailing `0x00` byte appended |

Including the public key `Y` in `challenge_generation` prevents rogue-key attacks where an adversary crafts a key that produces valid-looking proofs for someone else's VRF output. The domain separators prevent cross-protocol hash collisions where identical byte strings could be valid input to different hash operations. These are security fixes, not formatting changes.

RFC 9381 publishes test vectors for P-256 and Ed25519 but none for secp256k1. This project fills both gaps - a correct RFC 9381 implementation for secp256k1, and the test vectors to prove it.

## Why secp256k1?

Ed25519 and P-256 both have RFC 9381 suites with published test vectors. They're good curves. If your system already uses one of them, you should probably use the matching VRF suite and skip this section entirely.

But if you're working in the Bitcoin, Ethereum, or broader fintech ecosystem, your infrastructure already speaks secp256k1 - and that changes the calculus.

**Regulatory and auditor familiarity.** If your VRF underpins a fairness system - sweepstakes, gaming, any context where an external auditor or regulator needs to verify the randomness is unbiased - the choice of curve matters beyond just security properties. secp256k1 is the curve auditors encounter in blockchain and fintech contexts. They have existing tooling for it, existing mental models for how key management works, and existing verification scripts. When an auditor can reuse their secp256k1 knowledge rather than learning Ed25519 point encoding from scratch, the compliance conversation gets shorter. That's not a cryptographic argument, it's a practical one - but practical matters when you're sitting across from a gaming commission.

**BIP32/BIP39 key hierarchy compatibility.** BIP32 hierarchical deterministic key derivation and BIP39 mnemonic seeds are secp256k1-native. If your key management already uses BIP32 hardened derivation - which is standard infrastructure in fintech and blockchain systems - the derived keys are secp256k1 keys. A secp256k1 VRF means you can derive VRF signing keys directly from that same HD wallet hierarchy without curve conversion or a separate key ceremony. Ed25519 has SLIP-0010 as an alternative for HD derivation, but it's less widely implemented, less thoroughly tooled, and not what your existing infrastructure is built around.

**Ecosystem and tooling depth.** Bitcoin and Ethereum adoption drove secp256k1 tooling into every major programming language, every major cloud KMS, and most hardware security infrastructure. HSMs, hardware wallets (Ledger, Trezor), cloud key management services, and threshold signing setups all support secp256k1 natively. This isn't theoretical support - it's battle-tested at scale, protecting real value. When your VRF key needs to live in an HSM or participate in a threshold signing ceremony, you want a curve that your infrastructure already handles.

**Key reuse across protocols.** If your system already holds secp256k1 keys for transaction signing, authentication, or other protocols, a secp256k1 VRF lets those same keys generate verifiable random outputs. One key, multiple uses, no cross-curve bridging, no additional key material to manage and secure. This isn't always desirable - key separation is a legitimate security practice - but when your threat model permits it, eliminating a separate VRF key ceremony removes operational complexity and a class of key management errors.

The short version: secp256k1 isn't a better curve than Ed25519 or P-256 in the abstract. It's the right curve when your existing infrastructure, regulatory environment, and key management are already built around it.

## How We Know It's Correct

The Python implementation serves as the reference oracle. Before generating any secp256k1 vectors, the oracle validates its algorithm logic against the RFC 9381 Appendix B test vectors for P-256 (ECVRF-P256-SHA256-TAI). Byte-identical output on the published P-256 vectors proves the algorithm is correct. Only then does it generate secp256k1 vectors.

Every other implementation (Go, Rust, TypeScript) must produce byte-identical output for every vector. Cross-implementation validation goes further: proofs generated by implementation A must verify in implementations B, C, and D - catching compensating bugs where an implementation generates slightly wrong proofs that it also wrongly accepts.

VRF prove with RFC 6979 nonce generation is fully deterministic. CI runs prove twice per vector per implementation and asserts identical output, catching accidental use of random nonces.

## Suite Parameters

| Parameter | Value |
|---|---|
| Suite | ECVRF-SECP256K1-SHA256-TAI |
| Curve | secp256k1 |
| Cofactor | 1 |
| Suite string | `0xFE` |
| Hash function | SHA-256 |
| `encode_to_curve` | try_and_increment (TAI) |
| `challenge_generation` | 5-point: `(Y, H, Gamma, U, V)` per RFC 9381 |
| Nonce generation | RFC 6979 (deterministic) |
| Proof format | 81 bytes: Gamma (33 bytes, compressed) ‖ c (16 bytes) ‖ s (32 bytes) |
| VRF output (beta) | 32 bytes |
| y-coordinate selection | Even (0x02 prefix) during `encode_to_curve` decompression |

## Repository Structure

```
ecvrf/
├── python/              # Reference oracle
│   ├── ecvrf.py         # Implementation
│   ├── generate.py      # Vector generation script
│   └── requirements.txt
├── go/                  # Go implementation
│   ├── ecvrf.go
│   ├── ecvrf_test.go
│   └── go.mod
├── rust/                # Rust implementation
│   ├── src/
│   │   └── lib.rs
│   ├── tests/
│   └── Cargo.toml
├── typescript/          # TypeScript implementation
│   ├── src/
│   │   └── ecvrf.ts
│   ├── test/
│   ├── package.json
│   └── tsconfig.json
├── vectors/             # Published test vectors
│   └── vectors.json
├── Makefile                # Build/test automation
└── .github/
    └── workflows/
        └── ci.yml
```

## Getting Started

### Prerequisites

- Python 3.12+
- Go 1.22+
- Rust (stable toolchain)
- Node.js 20+

### Clone

```bash
git clone https://github.com/atikayda/ecvrf.git
cd ecvrf
```

### Per-Language Setup

**Python** (reference oracle):
```bash
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python ecvrf.py          # runs P-256 self-validation
```

**Go**:
```bash
cd go
go test ./...
```

**Rust**:
```bash
cd rust
cargo test
```

**TypeScript**:
```bash
cd typescript
npm install
npm test
```

### Run All Tests

```bash
make test               # runs all four implementations + cross-validation
```

Key Makefile targets:

| Target | Description |
|---|---|
| `make test` | Run all implementation tests and cross-validation |
| `make test-python` | Python P-256 self-validation only |
| `make test-go` | Go tests only |
| `make test-rust` | Rust tests only |
| `make test-ts` | TypeScript tests only |
| `make test-cross` | Cross-implementation validation (NxN) |
| `make vectors` | Regenerate test vectors from the Python oracle |
| `make cli` | Build CLI binaries for Go, Rust, and TypeScript |
| `make clean` | Remove build artifacts |

## Usage

> These implementations are source packages, not published to any package registry. Use them as local dependencies or git dependencies as shown below.

### Python (Reference Oracle)

```bash
cd python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

```python
from ecvrf import SECP256K1_SHA256_TAI, ecvrf_prove, ecvrf_verify

suite = SECP256K1_SHA256_TAI
sk = bytes.fromhex("...")   # 32-byte secret key
alpha = b"my VRF input"

x = int.from_bytes(sk, byteorder="big")
pk = (x * suite.curve.generator).to_bytes("compressed")

pi = ecvrf_prove(suite, sk, alpha)                  # 81-byte proof
valid, beta = ecvrf_verify(suite, pk, pi, alpha)    # (True, 32-byte output) or (False, None)
```

### Go

```go
import ecvrf "github.com/atikayda/ecvrf"

sk := []byte{...}    // 32-byte secret key
alpha := []byte("my VRF input")

pk, err := ecvrf.DerivePublicKey(sk)        // []byte (33 bytes, compressed)
pi, err := ecvrf.Prove(sk, alpha)           // []byte (81 bytes)
valid, beta := ecvrf.Verify(pk, pi, alpha)  // bool, []byte (32 bytes) or nil
```

### Rust

Add as a git dependency in `Cargo.toml`:
```toml
[dependencies]
ecvrf = { git = "https://github.com/atikayda/ecvrf", subdirectory = "rust" }
```

```rust
use ecvrf::{prove, verify, derive_public_key};

let sk: [u8; 32] = /* 32-byte secret key */;
let alpha: &[u8] = b"my VRF input";

let pk = derive_public_key(&sk)?;          // [u8; 33] compressed public key
let pi = prove(&sk, alpha)?;               // [u8; 81]
let beta = verify(&pk, &pi, alpha)?;       // [u8; 32] or Error
```

### TypeScript

```typescript
import { prove, verify, getPublicKey } from "ecvrf-secp256k1-sha256-tai";

const sk = new Uint8Array(/* 32-byte secret key */);
const alpha = new Uint8Array(/* arbitrary-length input */);

const pk = getPublicKey(sk);                         // Uint8Array (33 bytes, compressed)
const pi = prove(sk, alpha);                         // Uint8Array (81 bytes)
const { valid, beta } = verify(pk, pi, alpha);       // { valid: boolean, beta: Uint8Array | null }
```

## Test Vectors

Vectors live in `vectors/vectors.json`. The file contains 50+ positive vectors and 15+ negative vectors covering:

**Positive vectors:**
- Empty, short, medium, and long alpha strings
- Binary alpha (invalid UTF-8, embedded null bytes)
- Multiple keys with the same alpha, same key with sequential alphas
- Edge-case keys: `sk = 1`, `sk = n-1`, `sk ≈ n/2`
- Both y-parities (0x02 and 0x03 compressed public key prefixes)
- `try_and_increment` counter at 0 (first attempt) and > 10 (high iteration count)
- Very long alpha (64KB+) testing multi-block SHA-256

**Negative vectors:**
- Tampered Gamma, c, and s bytes
- `s >= group order n`
- Valid proof with wrong public key or wrong alpha
- Truncated proof (< 81 bytes), extended proof (> 81 bytes)
- Gamma bytes that don't decompress to a valid curve point
- All-zero proof

### Vector Format

Each positive vector includes all intermediate values for debugging:

```json
{
  "label": "human-readable description of the test case",
  "sk": "hex-encoded secret key (32 bytes)",
  "pk": "hex-encoded compressed public key (33 bytes)",
  "alpha": "hex-encoded alpha string",
  "alpha_string": "UTF-8 decoded alpha (empty string if binary)",
  "h": "hex-encoded H point (encode_to_curve output)",
  "h_ctr": 0,
  "k": "hex-encoded RFC 6979 nonce",
  "gamma": "hex-encoded Gamma point",
  "u": "hex-encoded U point",
  "v": "hex-encoded V point",
  "c": "hex-encoded challenge (16 bytes)",
  "s": "hex-encoded scalar (32 bytes)",
  "pi": "hex-encoded proof (81 bytes)",
  "beta": "hex-encoded VRF output (32 bytes)"
}
```

Intermediate values (`h`, `k`, `gamma`, `u`, `v`, `c`, `s`) let implementers pinpoint exactly where their code diverges if a vector fails. You don't need to guess which step went wrong.

## Draft-05/06 vs RFC 9381 - Quick Reference

If you're porting an existing secp256k1 VRF implementation, check these three things:

### 1. Does `challenge_generation` include the public key?

Draft-05/06 hashes four points:
```
hash_input = suite_string || 0x02 || H || Gamma || U || V
```

RFC 9381 hashes five points plus a trailing separator:
```
hash_input = suite_string || 0x02 || Y || H || Gamma || U || V || 0x00
```

This is the critical change. Without `Y`, the construction is vulnerable to rogue-key attacks.

### 2. Are trailing `0x00` separators present on all hash operations?

RFC 9381 appends `0x00` to every hash input:
- `encode_to_curve`: `... || I2OSP(ctr, 1) || 0x00`
- `challenge_generation`: `... || point_to_string(V) || 0x00`
- `proof_to_hash`: `... || point_to_string(cofactor * Gamma) || 0x00`

### 3. Does `proof_to_hash` use domain separator `0x03`?

```
hash_input = suite_string || 0x03 || point_to_string(cofactor * Gamma) || 0x00
```

If any answer is "no," the implementation follows a draft, not RFC 9381. The outputs will be incompatible.

## CI

Vectors are committed to the repo. CI does not regenerate them. Instead:

1. Regenerate vectors into a temp file and diff against the committed `vectors/vectors.json` (catches oracle drift from library updates)
2. Run all four implementations against committed vectors in parallel
3. Assert byte-identical proof output and verification for every positive vector
4. Assert rejection for every negative vector
5. Run cross-implementation validation (NxN proof generation and verification)
6. Run determinism checks (prove twice, assert identical output)

## Non-Goals

This project intentionally does not:
- Support draft-05/06 compatibility modes
- Support curves other than secp256k1
- Support hash functions other than SHA-256
- Support `encode_to_curve` methods other than TAI
- Publish to package registries (may come later)
- Benchmark performance (correctness first)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to run tests, add test vectors, and submit pull requests.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report vulnerabilities.

## License

MIT
