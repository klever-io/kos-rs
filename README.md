# Klever Wallet Library for Rust (kos-rs)

kos-rs is an open-source library crafted to deliver fundamental low-level crypto-wallet capabilities for blockchain
actions and transactions. Built with Rust, it ensures top-tier security and versatile platform adaptability, positioning
it as a premier choice for constructing secure and high-performing blockchain solutions.

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
- [x] Binance Smart Chain (BSC)
- [x] Huobi Token (HT)
- [x] Syscoin NEVM (SYS_NEVM)
- [x] Polkadot (DOT)
- [x] Kusama (KSM)
- [x] Reef (REEF)
- [x] Shiden (SDN)
- [x] Astar (ASTR)
- [x] Centrifuge (CFG)
- [x] KILT
- [x] Altair
- [x] Moonriver (MOVR)
- [x] Moonbeam (GLMR)
- [x] Sui (SUI)
- [x] Avail (AVAIL)
- [x] Rollux
- [x] Avalanche (AVAX)
- [x] Arbitrum (ARB)
- [x] Base
- [x] Near (NEAR)
- [x] Fantom (FTM)
- [x] Chiliz (CHZ)
- [x] Optimism (OP)
- [x] Polygon zkEVM
- [x] Stolz
- [x] Solana (SOL)
- [x] Litecoin (LTC)
- [x] Syscoin (SYS)
- [x] Dogecoin (DOGE)
- [x] Dash
- [x] Digibyte (DGB)
- [x] Internet Computer (ICP)
- [x] XRP
- [x] Cardano (ADA)
- [x] Cosmos (ATOM)
- [x] Celestia (TIA)
- [x] Cudos
- [x] Aura
- [x] Aptos (APT)
- [x] Bitcoin Cash (BCH)
- [x] Acala (ACA)
- [x] Karura (KAR)

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

### Packages (Monorepo)

- `packages/kos/`: Core package implementing all cryptocurrency wallet operations, including cryptographic functions,
  curves, and basic offline wallet operations for each blockchain.
- `packages/kos-web/`:  Package responsible for exporting kos functionality to JavaScript bindings, providing methods
  for web-based implementations.
- `packages/kos-mobile/`: Package responsible for exporting kos functionality to mobile platforms, providing bindings
  for both iOS (Swift) and Android (Kotlin).

---

## Apps powered by kos-rs

The kos-rs library powers several key applications within the Klever ecosystem:

- [Klever Wallet for iOS](https://apps.apple.com/uy/app/klever-wallet-bitcoin-crypto/id1615064243)
- [Klever Wallet for Android](https://play.google.com/store/apps/details?id=finance.klever.bitcoin.wallet&hl=en)
- [Klever Wallet for Browser (Extension)](https://chromewebstore.google.com/detail/klever-wallet/ifclboecfhkjbpmhgehodcjpciihhmif)

#### Open a pull request to include your app here.
---
[Download Klever Wallet - The best multi-chain crypto wallet](https://klever.io)
