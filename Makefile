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