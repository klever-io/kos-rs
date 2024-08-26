# Klever Wallet Library for Rust (kos-rs)

kos-rs is an open-source library crafted to deliver fundamental low-level crypto-wallet capabilities for blockchain actions and transactions. Built with Rust, it ensures top-tier security and versatile platform adaptability, positioning it as a premier choice for constructing secure and high-performing blockchain solutions.

#### KleverOS, which stands for Klever Wallet Ops Security, is a robust library meticulously crafted in Rust to guarantee the utmost security in private key generation while ensuring unparalleled auditability.

## Features

- Cross-platform compatibility.
- Low-level blockchain wallet features.
- Transaction handling.
- Robust security measures.
- Open-source and community-driven.

#### Initially, kos-rs offers support for the following blockchain networks and its sub tokens:

- [x] Bitcoin (BTC)
- [x] Ethereum (ETH)
- [x] Tron (TRX)
- [x] Klever (KLV)
- [x] Polygon (Matic)

## Getting Started with Javascript and Node.js

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

---
### Apps powered by kos-rs
The kos-rs library powers several key applications within the Klever ecosystem:

[Klever Wallet for iOS](https://apps.apple.com/uy/app/klever-wallet-bitcoin-crypto/id1615064243)
[Klever Wallet for Android](https://play.google.com/store/apps/details?id=finance.klever.bitcoin.wallet&hl=en)
[Klever Wallet for Browser (Extension)](https://chromewebstore.google.com/detail/klever-wallet/ifclboecfhkjbpmhgehodcjpciihhmif)

Open a pull request to include your app here.
---
[Download Klever Wallet - The best multi-chain crypto wallet](https://onelink.to/455hxv)
