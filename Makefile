.PHONY: all fmt webpack webpack-npm

fmt:
	cargo fmt --all -- --check

webpack:
	wasm-pack build --target web --out-dir ./demo/kos ./packages/kos

webpack-npm:
	wasm-pack build --target bundler --out-dir ../../demo/kos ./packages/kos
