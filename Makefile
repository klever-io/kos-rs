.PHONY: all fmt webpack webpack-npm

all: fmt
	cargo build

fmt:
	cargo fmt --all -- --check

webpack:
	wasm-pack build --target web --out-dir ../../demo/kos ./packages/kos

webpack-npm:
	wasm-pack build --scope klever --target bundler --release --out-dir ../../demo/kos ./packages/kos
