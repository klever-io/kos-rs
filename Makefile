.PHONY: all fmt clippy check webpack webpack-npm grcov

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

build-go-musl:	
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3 && \
	cargo build --profile min-size --target x86_64-unknown-linux-musl --package kos-mobile && \
	uniffi-bindgen-go --library target/x86_64-unknown-linux-musl/min-size/libkos_mobile.a --out-dir ./packages/kos-go

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
