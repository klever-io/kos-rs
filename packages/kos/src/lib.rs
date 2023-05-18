use kos_crypto::mnemonic::generate_mnemonic;
pub use kos_sdk::*;
use kos_types::error::Error;

use wasm_bindgen::prelude::*;

/// Generates a random mnemonic phrase given the number of words to generate, `count`.
#[wasm_bindgen(js_name = "generateMnemonicPhrase")]
pub fn generate_mnemonic_phrase(count: usize) -> Result<String, Error> {
    Ok(generate_mnemonic(count)?.to_phrase())
}
