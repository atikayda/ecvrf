# Contributing

Contributions are welcome. This project implements RFC 9381 ECVRF-SECP256K1-SHA256-TAI across twelve languages, so changes need care to maintain spec compliance and cross-implementation consistency.

## Running Tests

```bash
make test          # Run all tests (all 12 implementations + cross-validation)
make test-python   # Python oracle only
make test-go       # Go only
make test-rust     # Rust only
make test-ts       # TypeScript only
make test-c        # C only
make test-csharp   # C# only
make test-kotlin   # Kotlin only
make test-haskell  # Haskell only
make test-zig      # Zig only
make test-swift    # Swift only
make test-solidity # Solidity (Foundry) only
make test-solana   # Solana only
make test-cross    # Cross-implementation validation
make vectors       # Regenerate test vectors from the Python oracle
make cli           # Build CLI binaries for Go, Rust, and TypeScript
make clean         # Remove build artifacts
```

## Adding Test Vectors

1. Edit `python/generate.py` to add new vector definitions
2. Run `make vectors` to regenerate `vectors/vectors.json`
3. Run `make test` to confirm all twelve implementations pass against the updated vectors
4. Commit both `generate.py` and `vectors.json` together

## Code Style

- **Python:** PEP 8, type hints where practical
- **Go:** `gofmt`, standard library conventions
- **Rust:** `cargo fmt`, `cargo clippy` clean
- **TypeScript:** strict mode, no `any` types
- **C:** C11, consistent formatting with the existing `ecvrf.c`/`ecvrf.h` style
- **C#:** standard .NET conventions, namespace `Ecvrf`
- **Kotlin:** Kotlin coding conventions, Gradle/Kotlin DSL
- **Haskell:** consistent with existing module style, avoid unnecessary dependencies
- **Zig:** follow Zig standard library conventions, zero external dependencies
- **Swift:** Swift API Design Guidelines, Swift 5.9+
- **Solidity:** Solidity Style Guide, Foundry project conventions
- **Solana:** Rust conventions, compatible with Solana BPF toolchain

## Pull Request Requirements

- All twelve implementations must pass (`make test`)
- Cross-validation must pass (`make test-cross`)
- If adding vectors, include the regenerated `vectors/vectors.json`
- Changes must not break RFC 9381 compliance — the implementations must remain compatible with the published spec

## RFC 9381 Compliance

This project strictly follows [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381). Algorithm changes that deviate from the spec will not be accepted. If you believe the implementation diverges from the RFC, open an issue with the specific section reference.
