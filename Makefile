.PHONY: all fmt clippy check test webpack webpack-npm grcov build-go build-go-mac build-go-mac-intel build-go-musl docker-build-go docker-build-go-gnu docker-build-go-gnu-arm64 docker-build-go-musl docker-build-go-musl-arm64

UNAME := $(shell uname)

all: fmt
	cargo build -j4

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
	cargo build -j4 --package kos-hardware --target thumbv7em-none-eabihf --profile hardware

build-android:
	cd packages/kos-mobile && ./build_android.sh

publish-android:
	cd packages/kos-mobile/android && ./gradlew lib:publishKOSPublicationToGithubPackagesRepository

build-ios:
	cd packages/kos-mobile && ./build_ios.sh

build-go:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0 && \
	cargo build --release --package kos-mobile && uniffi-bindgen-go --library target/release/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/linux-amd64/ && \
	cp target/release/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-amd64/

docker-build-go: docker-build-go-gnu docker-build-go-gnu-arm64 docker-build-go-musl docker-build-go-musl-arm64

docker-build-go-gnu:
	docker build --platform linux/amd64 -t kos-go-builder-gnu-amd64 -f docker/gnu.dockerfile .
	docker run --platform linux/amd64 --rm -e CARGO_TARGET_DIR=/tmp/target -v $(PWD):/workspace kos-go-builder-gnu-amd64 bash -c "\
		cargo build --locked --release --package kos-mobile && \
		uniffi-bindgen-go --library /tmp/target/release/libkos_mobile.a --out-dir ./packages/kos-go && \
		mkdir -p ./packages/kos-go/kos_mobile/lib/linux-amd64/ && \
		cp /tmp/target/release/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-amd64/ && \
		strip ./packages/kos-go/kos_mobile/lib/linux-amd64/libkos_mobile.so"

docker-build-go-gnu-arm64:
	docker build --platform linux/arm64 -t kos-go-builder-gnu-arm64 -f docker/gnu.dockerfile .
	docker run --platform linux/arm64 --rm -e CARGO_TARGET_DIR=/tmp/target -v $(PWD):/workspace kos-go-builder-gnu-arm64 bash -c "\
		cargo build --locked --release --package kos-mobile && \
		uniffi-bindgen-go --library /tmp/target/release/libkos_mobile.a --out-dir ./packages/kos-go && \
		mkdir -p ./packages/kos-go/kos_mobile/lib/linux-arm64/ && \
		cp /tmp/target/release/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-arm64/ && \
		strip ./packages/kos-go/kos_mobile/lib/linux-arm64/libkos_mobile.so"

docker-build-go-musl:
	docker build --platform linux/amd64 -t kos-go-builder-musl-amd64 -f docker/alpine.dockerfile .
	docker run --platform linux/amd64 --rm -e CARGO_TARGET_DIR=/tmp/target -v $(PWD):/workspace kos-go-builder-musl-amd64 sh -c "\
		cargo build --locked --profile min-size --package kos-mobile && \
		mkdir -p ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ && \
		cp /tmp/target/min-size/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ && \
		strip ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/libkos_mobile.so"

docker-build-go-musl-arm64:
	docker build --platform linux/arm64 -t kos-go-builder-musl-arm64 -f docker/alpine.dockerfile .
	docker run --platform linux/arm64 --rm -e CARGO_TARGET_DIR=/tmp/target -v $(PWD):/workspace kos-go-builder-musl-arm64 sh -c "\
		cargo build --locked --profile min-size --package kos-mobile && \
		mkdir -p ./packages/kos-go/kos_mobile/lib/linux-musl-arm64/ && \
		cp /tmp/target/min-size/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-musl-arm64/ && \
		strip ./packages/kos-go/kos_mobile/lib/linux-musl-arm64/libkos_mobile.so"

build-go-mac:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0 && \
	cargo build --release --package kos-mobile && uniffi-bindgen-go --library target/release/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/darwin-aarch64/ && \
	cp target/release/libkos_mobile.dylib ./packages/kos-go/kos_mobile/lib/darwin-aarch64/

build-go-mac-intel:
	rustup target add x86_64-apple-darwin
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0 && \
	cargo build --release --target x86_64-apple-darwin --package kos-mobile && \
	uniffi-bindgen-go --library target/x86_64-apple-darwin/release/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/darwin-amd64/ && \
	cp target/x86_64-apple-darwin/release/libkos_mobile.dylib ./packages/kos-go/kos_mobile/lib/darwin-amd64/

build-go-musl:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0 && \
	cargo build --profile min-size --target x86_64-unknown-linux-musl --package kos-mobile && \
	uniffi-bindgen-go --library target/x86_64-unknown-linux-musl/min-size/libkos_mobile.a --out-dir ./packages/kos-go
	mkdir -p ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ && \
	cp target/x86_64-unknown-linux-musl/min-size/libkos_mobile.so ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/ && \
	strip ./packages/kos-go/kos_mobile/lib/linux-musl-amd64/libkos_mobile.so

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
