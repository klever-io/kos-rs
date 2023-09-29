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

- [x] Bitcoin (BTC)
- [x] Ethereum (ETH)
- [x] Tron (TRX)
- [x] Klever (KLV)
- [x] Polygon (Matic)

## Getting Started with Javascript and Node.js

```sh
npm i @klever/kos
```

## Getting Started with Android

Follow these steps in order to build the `.so` files that will be included in the Android project later.

### 1 - Preparing the enviroment for build

In order to build the `.so` files, there is some dependencies and configs needed.

- Install Rust - [Rust](https://www.rust-lang.org/tools/install)

- Install the latest version of Android NDK

  - To install the Android NDK, open the SDK Manager in Android Studio and select the latest version os NDK in the "SDK Tools tab".
  - Click "Apply" and follow the instructions.
  - After the installation completes, you need to set the `NDK_HOME` env to the path NDK is istalled.

- Install the latest version of CMake tool

  - To install CMake, open the SDK Manager in Android Studio and select one version of CMake tool in the "SDK Tools tab".
  - Click "Apply" and follow the instructions.

- Install `openssl`
  - In MacOS, you can use brew: `brew install openssl@3`
- After install, you need to set the `OPENSSL_DIR` env pointing to the path openssl is istalled. Also, this env must be included to the `PATH`.

- Cargo Linker Config

  - In order to the linker work properly during the build, you need to teel Cargo the path to the clang files of each architecture.
  - First, if it is not already created, create the config file `touch ~/.cargo/config`

  - Set the path for each architecture as in the following example:

  ```sh
      [target.aarch64-linux-android]
      linker = "path-to-the-clang-aarch64-file"

      [target.armv7-linux-androideabi]
      linker = "path-to-the-clang-armv7-file"

      [target.i686-linux-android]
      linker = "path-to-the-clang-i686-file"

      [target.x86_64-linux-android]
      linker = "path-to-the-clang-x86_64-file"

  ```

  - Is important to set the absolute path for the clang files in the config, without using env variables. Ussually the clang files are located inside the NDK_HOME folder. Like this: `$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang`.

### 2 - Clone the repo

```sh
git clone git@github.com:klever-io/kos-rs.git
```

### 3 - Add output files to the Android project

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
