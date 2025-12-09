.PHONY: all fmt clippy check test webpack webpack-npm grcov build-go build-go-mac build-go-musl

UNAME := $(shell uname)

all: fmt
	cargo build

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all -- -D warnings

check: fmt clippy
	cargo deny check
#	cargo outdated --exit-code 1
	cargo pants

test: fmt clippy
	cargo test --workspace --exclude kos-hardware

grcov:
	cargo build
	cargo test
# todo: fix grcov
# grcov ./target/debug/ -s . -t lcov --llvm --branch --ignore-not-existing --ignore "/*" -o lcov.info

webpack:
	wasm-pack build --scope klever --target web --out-name index --out-dir ../../packages/kos-web/demo/kos ./packages/kos-web

webpack-npm:
	wasm-pack build --scope klever --target bundler --release --out-name index --out-dir ../../packages/kos-web/demo/kos ./packages/kos-web

clean-mobile-build:
	cd packages/kos-mobile && ./build_clean.sh

build-ksafe:
	cargo build --package kos-hardware --target thumbv7em-none-eabihf --profile hardware

build-android:
	cd packages/kos-mobile && ./build_android.sh

publish-android:
	cd packages/kos-mobile/android && ./gradlew lib:publishKOSPublicationToGithubPackagesRepository

build-ios:
	cd packages/kos-mobile && ./build_ios.sh

build-go:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3 && \
	cargo build --release --package kos-mobile && uniffi-bindgen-go --library target/release/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/linux-amd64/ && \
	cp target/release/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-amd64/ || \
	(echo "Error: Failed to copy libkos_mobile.so"; exit 1)

build-go-mac:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3 && \
	cargo build --release --package kos-mobile && uniffi-bindgen-go --library target/release/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/darwin-aarch64/ && \
	cp target/release/libkos_mobile.dylib ./packages/kos-go/kos_mobile/lib/darwin-aarch64/ || \
	(echo "Error: Failed to copy libkos_mobile.dylib"; exit 1)

build-go-musl:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3 && \
	cargo build --profile min-size --target x86_64-unknown-linux-musl --package kos-mobile && \
	uniffi-bindgen-go --library target/x86_64-unknown-linux-musl/min-size/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ && \
	cp target/x86_64-unknown-linux-musl/min-size/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ || \
	(echo "Error: Failed to copy libkos_mobile.so from musl build"; exit 1)

test-ios: build-ios
	cd packages/kos-mobile/ios/framework/KOSMobile && xcodebuild \
	-project KOSMobile.xcodeproj \
	-scheme KOSMobile \
	-sdk iphonesimulator \
	-destination 'platform=iOS Simulator,OS=17.2,name=iPhone 15 Pro' \
	CODE_SIGNING_ALLOWED=NO \
	test

test-android: build-android
	cd packages/kos-mobile/android && ./gradlew lib:testDebugUnitTest
