#!/bin/bash

set -o pipefail
set -e

build()
{
  target=$1
  flags=$2
  cargo build --manifest-path packages/kos-ios/Cargo.toml --release --lib --target $target $flags
}

rm -rf build/include
mkdir -p build/include
cbindgen $(pwd)/packages/kos-ios/src/lib.rs -l c > build/include/libkos.h

echo "Init ios build"
cargo clean

echo "Building for ios"
build aarch64-apple-ios $1
echo "Building for ios-sim" 
build aarch64-apple-ios-sim $1
echo "Building for ios-sim"
build x86_64-apple-ios $1

echo "Creating universal library"
cp target/aarch64-apple-ios/release/libkos.a build/libkos-ios.a

echo "Creating universal library for ios-sim"
lipo -create \
		target/aarch64-apple-ios-sim/release/libkos.a \
		target/x86_64-apple-ios/release/libkos.a \
		-output build/libkos-ios-sim.a

rm -f build/libkos-ios.a build/libkos-ios-sim.a