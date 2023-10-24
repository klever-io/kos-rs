# KleverOS Library for Rust (kos-rs)

kos-rs is an open-source, cross-platform library designed to provide essential low-level functionality for blockchain wallet operations and transactions. Developed in Rust, it offers robust security and platform flexibility, making it an excellent choice for building secure and efficient blockchain applications.

#### KleverOS, which stands for Klever Wallet Ops Security, is a robust library meticulously crafted in Rust to guarantee the utmost security in private key generation while ensuring unparalleled auditability.

## Features

- Cross-platform compatibility.
- Low-level blockchain wallet features.
- Transaction handling.
- Robust security measures.
- Open-source and community-driven.

#### Initially, kos-rs offers support for the following blockchain networks and its sub tokens:

[x] Bitcoin (BTC)
[x] Ethereum (ETH)
[x] Tron (TRX)
[x] Klever (KLV)
[x] Polygon (Matic)

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

# Klever Bounty Program (kos-rs)

## Overview

Klever is on a quest for adept Rust developers to revamp its Rust-powered crypto wallet SDK, initially designed for WebAssembly (Wasm). The aim is to expand its compatibility for Kotlin (Android) and Swift (iOS) platforms. The ultimate objective is to streamline this transition, minimizing the manual coding interventions.

## Reward Distribution

Bounty winners will be compensated with $KFI tokens. Here's the reward distribution:

[x] Web (Rust SDK binding): 10,000 KFI
[x] React Native (Rust SDK binding): 10,000 KFI
[ ] Kotlin (Rust SDK binding): 10,000 KFI
[ ] Swift (Rust SDK binding): 10,000 KFI
[ ] Code Review PR Approval: 100 KFI

## Key Milestones

### 1. SDK Examination

- Perform an in-depth review of the present SDK, focusing on its architecture, features, and Wasm-specific dependencies.

### 2. Integration & Accessibility

- Create essential bindings and exports to make Rust functions and types accessible from Wasm, Kotlin, and Swift.

### 3. Security Assurance

- Probe the existing and newly-developed code for potential threats and make necessary patches.

### 4. Automation Implementation

- Conceptualize and establish an automatic adaptation system, preferably using Rust's attributes/macros. This should ensure the central Rust code remains universally applicable.

### 5. Validation

- Rigorously test the SDK for Kotlin and Swift platforms, ensuring uniformity.
- Integrate critical unit tests to validate performance.

### 6. Documentation & Guidance

- Deliver a detailed summary of the alterations and explain the workings of the automation tool.
- Detail the integration process for Kotlin and Swift projects.

### 7. Evidence of Testing

- Produce provable test results for Kotlin and Swift platforms, including unit, integration, and other relevant test artifacts.

## Evaluation Criteria

- Effortless SDK integration with Kotlin and Swift.
- Uniform SDK operations across Wasm, Kotlin, and Swift.
- Significant minimization of manual code changes due to the automation tool.
- Transparent and coherent documentation aiding seamless SDK integration for new developers.

## Recommendations

- To genuinely grasp the SDK's intricacies, having access or a sample of the existing Rust SDK is crucial. This aids in a well-informed transition.
- The program should prioritize developers familiar with Rust FFI and Kotlin/Swift compatibility. This focus promises higher-quality, viable solutions.

### Final Words

We're eager to witness the pioneering solutions our community will present. Accomplishing this bounty's objectives will immensely boost our SDK's adaptability and appeal, enriching both developers and end-users.


