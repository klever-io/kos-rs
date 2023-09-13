# kos-rs

## Project Directory Structure

- `Makefile`: Main project build and automation configuration.
- `demo/`: JavaScript demo page with instructions on how to use the `kos-rs` library in web applications.

### Packages (Monorepo)

- `packages/kos/`: Contains tools and utilities for exporting WebAssembly, designed for use in WebAssembly operations.
- `packages/kos-crypto/`: Cryptographic package with support for crypto curves for transaction signing, including asymmetric and symmetric cryptography.
- `packages/kos-proto/`: Library for building protocol messages.
- `packages/kos-sdk/`: Package for blockchain integration, wallet management, transaction construction, and signing implementations.
- `packages/kos-types/`: Package containing complex data types and helpful utilities.
- `packages/kos-utils/`: Package with utility libraries for various purposes.
