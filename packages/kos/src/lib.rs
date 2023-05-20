use kos_crypto::mnemonic::generate_mnemonic;
pub use kos_sdk::*;
use kos_types::error::Error;
use kos_utils::logger;

use wasm_bindgen::prelude::*;

// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    logger::init(logger::Config::default());

    log::info!("KOS Module initialized");

    Ok(())
}

/// Generates a random mnemonic phrase given the number of words to generate, `count`.
#[wasm_bindgen(js_name = "generateMnemonicPhrase")]
pub fn generate_mnemonic_phrase(count: usize) -> Result<String, Error> {
    Ok(generate_mnemonic(count)?.to_phrase())
}
