use crate::chain::BaseChain;
use crate::models::{self, BroadcastResult, Transaction};
use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct NONE;
pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "None",
    symbol: "NONE",
    precision: 0,
    chain_code: 0,
};

#[wasm_bindgen]
impl NONE {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(_private_key: &[u8]) -> Result<KeyPair, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        _mnemonic: &str,
        _path: &str,
        _password: Option<String>,
    ) -> Result<KeyPair, Error> {
        Ok(KeyPair::new_default())
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(_private_key: &KeyPair) -> Result<String, Error> {
        Ok("NONE".into())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(_index: u32, _is_legacy: Option<bool> ) -> Result<String, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(_digest: &[u8], _keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<bool, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(_data: Transaction, _keypair: &KeyPair) -> Result<Transaction, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(_message: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(_message: &[u8], _keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        _message: &[u8],
        _signature: &[u8],
        _address: &str,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "getBalance")]
    /// Get balance of address and token
    /// If token is None, it will return balance of native token
    /// If token is Some, it will return balance of token
    /// If node_url is None, it will use default node url
    pub async fn get_balance(
        _address: &str,
        _token: Option<String>,
        _node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    pub async fn send(
        _sender: String,
        _receiver: String,
        _amount: BigNumber,
        _options: Option<models::SendOptions>,
        _node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        _data: crate::models::Transaction,
        _node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        _address: &str,
        _option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedChain("NONE"))
    }
}
