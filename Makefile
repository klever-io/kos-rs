.PHONY: all fmt webpack webpack-npm grcov

all: fmt
	cargo build

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all -- -D warnings

grcov:
	cargo build
	cargo test
# todo: fix grcov
# grcov ./target/debug/ -s . -t lcov --llvm --branch --ignore-not-existing --ignore "/*" -o lcov.info

webpack:
	wasm-pack build --scope klever --target web --out-name index --out-dir ../../demo/kos ./packages/kos

webpack-npm:
	wasm-pack build --scope klever --target bundler --release --out-name index --out-dir ../../demo/kos ./packages/kos
