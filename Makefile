.PHONY: all fmt clippy check webpack webpack-npm grcov

UNAME := $(shell uname)

all: fmt
	cargo build

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all -- -D warnings

encode-env:
ifeq ($(UNAME), Linux)
	cat packages/kos-sdk/.env.nodes | base64 -w 0 > .env.nodes.base64
endif
ifeq ($(UNAME), Darwin)
	cat packages/kos-sdk/.env.nodes | base64 > .env.nodes.base64
endif

check: fmt clippy
	cargo deny check
	cargo outdated --exit-code 1
	cargo pants

grcov:
	cargo build
	cargo test
# todo: fix grcov
# grcov ./target/debug/ -s . -t lcov --llvm --branch --ignore-not-existing --ignore "/*" -o lcov.info

webpack:
	wasm-pack build --scope klever --target web --out-name index --out-dir ../../demo/kos ./packages/kos

webpack-npm:
	wasm-pack build --scope klever --target bundler --release --out-name index --out-dir ../../demo/kos ./packages/kos

ios: header
# rustup target add aarch64-apple-ios aarch64-apple-darwin x86_64-apple-ios x86_64-apple-darwin
	@cargo build --manifest-path packages/kos-ios/Cargo.toml --release --lib --target aarch64-apple-ios
	@cargo build --manifest-path packages/kos-ios/Cargo.toml --release --lib --target aarch64-apple-ios-sim
	@cargo build --manifest-path packages/kos-ios/Cargo.toml --release --lib --target=x86_64-apple-ios

	@cp target/aarch64-apple-ios/release/libkos.a build/libkos-ios.a
	
	@lipo -create \
		target/aarch64-apple-ios-sim/release/libkos.a \
		target/x86_64-apple-ios/release/libkos.a \
		-output build/libkos-ios-sim.a

macos:
	@cargo build --release --lib --target aarch64-apple-darwin
	@cargo build --release --lib --target x86_64-apple-darwin
	@cargo +nightly build -Z build-std --release --lib --target aarch64-apple-ios-macabi
	@cargo +nightly build -Z build-std --release --lib --target x86_64-apple-ios-macabi
	
	@$(RM) -rf build/libkos-macos.a
	@$(RM) -rf build/libkos-maccatalyst.a
	
	@lipo -create -output build/libkos-macos.a \
					target/aarch64-apple-darwin/release/libkos.a \
					target/x86_64-apple-darwin/release/libkos.a
	
	@lipo -create -output build/libkos-maccatalyst.a \
					target/aarch64-apple-ios-macabi/release/libkos.a \
					target/x86_64-apple-ios-macabi/release/libkos.a
		
xc:
	@xcodebuild -create-xcframework \
	-library build/libkos-ios-sim.a \
	-headers ./build/include/ \
	-library build/libkos-ios.a \
	-headers ./build/include/ \
	-output build/Kos.xcframework

header:
	@$(RM) -rf build/include
	@mkdir -p build/include
	@cbindgen $(shell pwd)/packages/kos-ios/src/lib.rs -l c > build/include/libkos.h