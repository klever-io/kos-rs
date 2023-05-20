pub mod address;
pub mod models;
pub mod requests;
use crate::{chain::BaseChain, models::BroadcastResult};
use kos_crypto::{ed25519::Ed25519KeyPair, keypair::KeyPair};
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use sha3::{Digest, Keccak256};
use std::todo;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen()]
pub struct KLV {}

pub const SIGN_PREFIX: &[u8; 24] = b"\x17Klever Signed Message:\n";
pub const BIP44_PATH: u32 = 690;
pub const BIP44_PATH_TESTNET: u32 = 620;

#[wasm_bindgen]
impl KLV {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BaseChain {
            name: "Klever",
            symbol: "KLV",
            precision: 6,
            node_url: "https://node.mainnet.klever.finance",
        }
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::random(&mut rng);
        Ok(KeyPair::new_ed25519(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        let kp = Ed25519KeyPair::new_from_mnemonic_phrase_with_path(
            mnemonic,
            path,
            password.as_deref(),
        )?;

        Ok(KeyPair::new_ed25519(kp))
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(keypair: &KeyPair) -> Result<String, Error> {
        Ok(address::Address::from_keypair(&keypair).to_string())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(index: u32) -> Result<String, Error> {
        Ok(format!("m/44'/{}'/0'/0'/{}'", BIP44_PATH, index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let sig = keypair.sign_digest(digest);
        Ok(sig)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<(), Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(data: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        Ok(keypair.sign_digest(data))
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        let mut hasher = Keccak256::new();
        hasher.update(to_sign);
        let digest = hasher.finalize();
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(_message: &[u8], _keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        _message: &[u8],
        _signature: &[u8],
        _address: &str,
    ) -> Result<(), Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "getBalance")]
    /// Get balance of address and token
    /// If token is None, it will return balance of native token
    /// If token is Some, it will return balance of token
    /// If node_url is None, it will use default node url
    pub async fn get_balance(
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let acc = requests::get_account(node_url, address).await.unwrap();
        match token {
            Some(key) => {
                if key == "KLV" {
                    return Ok(BigNumber::from(acc.balance.unwrap_or(0)));
                }

                match acc.assets.unwrap().get(&key) {
                    Some(asset) => Ok(BigNumber::from(asset.balance)),
                    None => Ok(BigNumber::from(0)),
                }
            }
            None => Ok(BigNumber::from(acc.balance.unwrap_or(0))),
        }
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        data: Vec<u8>,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let result = requests::broadcast(node_url, &data).await?;

        match result.get("data") {
            Some(v) => match v.as_object() {
                Some(obj) => {
                    let tx_hash = Hash::new(obj.get("txHash").unwrap().as_str().unwrap())?;
                    return Ok(BroadcastResult::new(tx_hash, data));
                }
                None => {}
            },
            None => {}
        }

        match result.get("error") {
            Some(err) => return Err(Error::ReqwestError(err.to_string())),
            None => Err(Error::ReqwestError("Unknown error".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use super::*;
    use hex::FromHex;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d";
    const DEFAULT_ADDRESS: &str = "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Ed25519KeyPair::new(b.into());
        KeyPair::from(kp)
    }

    #[test]
    fn test_get_galance() {
        let balance = tokio_test::block_on(KLV::get_balance(
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            Some("KLV".to_string()),
            None,
        ))
        .unwrap();
        println!("balance: {}", balance.to_string());
        println!("balance: {}", balance.with_precision(6));

        assert_eq!("0", balance.to_string());
    }

    #[test]
    fn test_broadcast() {
        let result = tokio_test::block_on(
            KLV::broadcast(
                "{\"tx\":{\"RawData\":{\"Nonce\":13,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBIDS0xWGAo=\"}}],\"KAppFee\":500000,\"BandwidthFee\":1000000,\"Version\":1,\"ChainID\":\"MTAwNDIw\"},\"Signature\":[\"O7C2MjTUMauWl8kfeJjgwDnFLkiDqY2U23s6AWzTstut63FnZeKC3EcxY0DiAgzf5PQ1+jeC2dIx3+pP7BHlBQ==\"]}}"
                .as_bytes().to_vec(),
                Some("https://node.testnet.klever.finance".to_string()),
        ));
        println!("result: {:?}", result);
    }

    #[test]
    fn test_address_from_mnemonic() {
        let path = KLV::get_path(0).unwrap();
        let kp = KLV::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", &path, None).unwrap();
        let address = KLV::get_address_from_keypair(&kp).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_address_from_private_key() {
        let address = KLV::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address.to_string());
    }
}
