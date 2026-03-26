# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it through [GitHub Security Advisories](https://github.com/atikayda/ecvrf/security/advisories/new) rather than opening a public issue.

Alternatively, email security concerns to **kaity@atikayda.com** with the subject line `[ecvrf] Security Report`.

We will acknowledge reports within 72 hours and provide a timeline for resolution.

## Security Model

These are **reference implementations** of ECVRF-SECP256K1-SHA256-TAI (RFC 9381), built for correctness and cross-implementation validation. They have **not been formally audited**.

### Side-Channel Resistance

| Implementation | Library | Constant-Time |
|---|---|---|
| Python (oracle) | `ecdsa` (pure Python) | No |
| Go | `decred/dcrd/dcrec/secp256k1` | Yes |
| Rust | `k256` (RustCrypto) | Yes |
| TypeScript | `@noble/curves` | Yes |
| C | OpenSSL `libcrypto` | Yes |
| C# | BouncyCastle .NET (managed) | No |
| Kotlin | BouncyCastle Java (managed) | No |
| Haskell | Pure hand-rolled arithmetic | No |
| Zig | `std.crypto.ecc.Secp256k1` | Yes |
| Swift | `libsecp256k1` (via swift-secp256k1) | Yes |
| Solidity (EVM) | EVM opcodes | N/A (on-chain) |
| Solana (SVM) | `secp256k1_recover` syscall | N/A (on-chain) |

**Python:** The Python implementation uses the pure-Python `ecdsa` library, which is **not constant-time** and is vulnerable to timing side-channels. It exists solely as a reference oracle for generating and validating test vectors. Do not use it for production secret key operations.

**Go, Rust, TypeScript, C, Zig, Swift:** These implementations use constant-time elliptic curve libraries and are suitable for use with secret keys. However, none have undergone formal security audits. Use in production at your own risk.

**C#, Kotlin:** These use BouncyCastle's managed (JVM/.NET) big-integer arithmetic, which is **not constant-time**. Suitable for verification of public data, but avoid using for secret key operations in timing-sensitive environments.

**Haskell:** All elliptic curve arithmetic is hand-rolled in pure Haskell with no constant-time guarantees. Not suitable for secret key operations in timing-sensitive environments.

**Solidity, Solana:** On-chain execution is publicly visible and deterministic - all inputs, outputs, and execution traces are observable by design. Timing side-channels are not applicable in this context.

### Suite String

The suite string `0xFE` used for ECVRF-SECP256K1-SHA256-TAI is an **unregistered community convention**, not an IANA-assigned value. RFC 9381 does not define a suite for secp256k1. If IANA assigns an official suite string for secp256k1 in the future, this project will update accordingly.

## Supported Versions

Only the latest version on the `main` branch receives security updates. 
