# KleverOS Library for Rust (kos-rs)

kos-rs is an open-source, cross-platform library designed to provide essential low-level functionality for blockchain wallet operations and transactions. Developed in Rust, it offers robust security and platform flexibility, making it an excellent choice for building secure and efficient blockchain applications.

#### KleverOS, which stands for Klever Wallet Ops Security, is a robust library meticulously crafted in Rust to guarantee the utmost security in private key generation while ensuring unparalleled auditability.

## Features

- Cross-platform compatibility.
- Low-level blockchain wallet features.
- Transaction handling.
- Robust security measures.
- Open-source and community-driven.

## Getting Started with Javascript

```sh
npm i @klever/kos
```

## Getting Started with Rust

Follow these instructions to get started with kos-rs in your Rust project.

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)

### Installation

To add kos-rs to your Rust project, simply include it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
kos-rs = "0.1"
```


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
