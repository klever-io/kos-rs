use crate::error::Error;
use kos::crypto::cipher;
use kos::crypto::mnemonic::generate_mnemonic;
use qrcode_generator::QrCodeEcc;
use wasm_bindgen::prelude::*;

mod models;
mod utils;

mod error;
mod number;
pub mod wallet;

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
        .map_err(|e| Error::InvalidString(format!("Invalid UTF-8 string: {e}")))
}

/// Decrypts the given data with the given password.
/// Data will have the algorithm tag prepended to it (1 byte).
#[wasm_bindgen(js_name = "decrypt")]
pub fn decrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, Error> {
    cipher::decrypt(data, password, iterations).map_err(|e| Error::Cipher(format!("{e}")))
}

/// Encrypt for GCM the given data with the given password.
/// Data will have the algorithm tag prepended to it (1 byte).
#[wasm_bindgen(js_name = "encrypt")]
pub fn encrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, Error> {
    cipher::encrypt(cipher::CipherAlgo::GCM, data, password, iterations)
        .map_err(|e| Error::Cipher(format!("{e}")))
}

/// Create pem file from tag and data
#[wasm_bindgen(js_name = "toPem")]
pub fn to_pem(tag: String, data: &[u8]) -> Result<String, Error> {
    let result = cipher::to_pem(tag, data)?;
    Ok(result.to_string())
}

/// Decrypt pem file to bytes
#[wasm_bindgen(js_name = "fromPem")]
pub fn from_pem(data: &str, password: &str, iterations: u32) -> Result<Vec<u8>, Error> {
    let pem = cipher::string_to_pem(data)?;
    decrypt(pem.contents(), password, iterations)
}

/// Create QRCode based on data
#[wasm_bindgen(js_name = "generateQR")]
pub fn generate_qr(data: &str) -> Result<Vec<u8>, Error> {
    qrcode_generator::to_png_to_vec(data, QrCodeEcc::Low, 1024)
        .map_err(|e| Error::InvalidString(format!("Invalid QRCode data: {e}")))
}

#[wasm_bindgen(js_name = "isChainSupported")]
pub fn is_chain_supported(chain: u32) -> bool {
    kos::chains::is_chain_supported(chain)
}

#[wasm_bindgen(js_name = "getPathByChain")]
pub fn get_path_by_chain(
    chain_id: u32,
    index: u32,
    use_legacy_path: bool,
) -> Result<String, Error> {
    let chain = kos::chains::get_chain_by_id(chain_id)
        .ok_or(Error::UnsupportedChain(format!("{chain_id}")))?;
    let path = chain.get_path(index, use_legacy_path);
    Ok(path)
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainData {
    pub id: u32,
    #[wasm_bindgen(skip)]
    pub name: String,
    #[wasm_bindgen(skip)]
    pub symbol: String,
}

#[wasm_bindgen]
impl ChainData {
    #[wasm_bindgen(js_name = getId)]
    pub fn get_id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(js_name = getName)]
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(js_name = getSymbol)]
    pub fn get_symbol(&self) -> String {
        self.symbol.clone()
    }
}

#[wasm_bindgen(js_name = "getSupportedChains")]
pub fn get_supported_chains_data() -> Vec<ChainData> {
    let ids = kos::chains::get_supported_chains();

    let mut chains_data = Vec::new();

    for id in ids {
        if let Some(chain) = kos::chains::get_chain_by_base_id(id) {
            chains_data.push(ChainData {
                id: chain.get_id(),
                name: chain.get_name().to_string(),
                symbol: chain.get_symbol().to_string(),
            });
        }
    }

    chains_data
}

#[wasm_bindgen(js_name = "getChainInfo")]
pub fn get_chain_info(id: u32) -> Option<ChainData> {
    kos::chains::get_chain_by_id(id).map(|chain| ChainData {
        id: chain.get_id(),
        name: chain.get_name().to_string(),
        symbol: chain.get_symbol().to_string(),
    })
}
