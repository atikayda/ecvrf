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

**Python:** The Python implementation uses the pure-Python `ecdsa` library, which is **not constant-time** and is vulnerable to timing side-channels. It exists solely as a reference oracle for generating and validating test vectors. Do not use it for production secret key operations.

**Go, Rust, TypeScript:** These implementations use constant-time elliptic curve libraries (`decred`, `k256`, `@noble/curves` respectively) and are suitable for use with secret keys. However, none have undergone formal security audits. Use in production at your own risk.

### Suite String

The suite string `0xFE` used for ECVRF-SECP256K1-SHA256-TAI is an **unregistered community convention**, not an IANA-assigned value. RFC 9381 does not define a suite for secp256k1. If IANA assigns an official suite string for secp256k1 in the future, this project will update accordingly.

## Supported Versions

Only the latest version on the `main` branch receives security updates. 
