pub mod api;

pub use kos_crypto::cipher::*;
use kos_crypto::cipher::{self, CipherAlgo};
use kos_crypto::mnemonic::generate_mnemonic;
pub use kos_sdk::*;
use kos_types::error::Error;
use kos_utils::logger;

use qrcode_generator::QrCodeEcc;

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

/// Converts the given string to bytes.
#[wasm_bindgen(js_name = "toBytes")]
pub fn to_bytes(data: &str) -> Result<Vec<u8>, Error> {
    Ok(data.as_bytes().to_vec())
}

/// Converts the given bytes to a string.
#[wasm_bindgen(js_name = "toString")]
pub fn to_string(data: &[u8]) -> Result<String, Error> {
    String::from_utf8(data.to_vec())
        .map_err(|e| Error::InvalidString(format!("Invalid UTF-8 string: {}", e.to_string())))
}

/// Encrypts the given data with the given password.
#[wasm_bindgen(js_name = "encrypt")]
pub fn encrypt(algo: CipherAlgo, data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    algo.encrypt(data, password)
}

/// Decrypts the given data with the given password.
/// Data will have the algorithm tag prepended to it (1 byte).
#[wasm_bindgen(js_name = "decrypt")]
pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    cipher::decrypt(data, password)
}

/// Create pem file from tag and data
#[wasm_bindgen(js_name = "toPem")]
pub fn to_pem(tag: String, data: &[u8]) -> Result<String, Error> {
    let result = cipher::to_pem(tag, data)?;
    Ok(result.to_string())
}

/// Decrypt pem file to bytes
#[wasm_bindgen(js_name = "fromPem")]
pub fn from_pem(data: &str, password: &str) -> Result<Vec<u8>, Error> {
    let pem = cipher::string_to_pem(data)?;
    decrypt(pem.contents(), password)
}

/// Create QRCode based on data
#[wasm_bindgen(js_name = "generateQR")]
pub fn generate_qr(data: &str) -> Result<Vec<u8>, Error> {
    qrcode_generator::to_png_to_vec(data, QrCodeEcc::Low, 1024)
        .map_err(|e| Error::InvalidString(format!("Invalid QRCode data: {}", e.to_string())))
}
