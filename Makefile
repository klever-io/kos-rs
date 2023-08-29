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
