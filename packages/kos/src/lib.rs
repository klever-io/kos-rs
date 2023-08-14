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

/// API Signature model
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct APISignature {
    #[wasm_bindgen(skip)]
    pub user: String,
    #[wasm_bindgen(skip)]
    pub nonce: u64,
    #[wasm_bindgen(skip)]
    pub message_hash: String,
    #[wasm_bindgen(skip)]
    pub signature: String,
}

impl APISignature {
    pub fn get_user(&self) -> String {
        self.user.clone()
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_message_hash(&self) -> String {
        self.message_hash.clone()
    }

    pub fn get_signature(&self) -> String {
        self.signature.clone()
    }
}

/// Create QRCode based on data
#[wasm_bindgen(js_name = "apiSignature")]
pub fn api_signature(
    private_key: String,
    client_id: String,
    nonce: u64,
) -> Result<APISignature, Error> {
    let nonce = if nonce == 0 {
        // current timestamp in ms
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    } else {
        nonce
    };

    println!("nonce: {}", nonce);

    // message prefix
    let prefix = "\x17KLEVER Signed Message:\n".as_bytes();

    // create token nonce
    let token_nonce = format!("{}/{}", nonce, client_id);
    // sha256 token nonce
    let token_nonce_hash = kos_crypto::hash::sha256(&token_nonce.as_bytes());
    let token_hash_len: [u8; 4] = [0, 0, 0, 32];
    // append prefix. message length and message
    let to_sign = vec![prefix, &token_hash_len, &token_nonce_hash].concat();
    // keccak256 hash
    let hash = kos_crypto::hash::keccak256(&to_sign);

    // convert hex prive key to bytes
    let pk = hex::decode(private_key).unwrap();
    // KLV KeyPair
    let mut pk_array: [u8; 32] = [0; 32];
    pk_array.copy_from_slice(&pk);

    let kp = kos_crypto::keypair::KeyPair::new_ed25519(kos_crypto::ed25519::Ed25519KeyPair::new(
        pk_array,
    ));

    // sign message
    let signature = kp.sign_digest(&hash);

    let addr = chains::KLV::get_address_from_keypair(&kp)?;

    Ok(APISignature {
        user: addr,
        nonce: nonce,
        message_hash: hex::encode(hash),
        signature: hex::encode(signature),
    })
}

#[cfg(test)]
mod test {
    use crate::api_signature;

    #[test]
    fn test_api_signature() {
        const DEFAULT_PRIVATE_KEY: &str =
            "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d";
        const CLIENT_ID: &str = "web-extension";

        let nonce = 1692031458346;

        let v = api_signature(
            DEFAULT_PRIVATE_KEY.to_string(),
            CLIENT_ID.to_string(),
            nonce,
        )
        .unwrap();

        println!("{:?}", v);

        assert_eq!(v.signature, "c24b408e710ca3be41fc6814e48857c226f869b13bc269a2a3c84cbd7ad89bc0433674fb816c92b656c1ea3fd18d1895d4fe56ab5427f8a50536060d5c400809")
    }
}
