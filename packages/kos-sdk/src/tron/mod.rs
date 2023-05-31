pub mod address;
pub mod requests;

use std::str::FromStr;

use crate::{
    chain::BaseChain,
    models::{self, BroadcastResult, Transaction, TransactionRaw},
};
use kos_crypto::{keypair::KeyPair, secp256k1::Secp256k1KeyPair};
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;

use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct TRX {}

pub const SIGN_PREFIX: &[u8; 22] = b"\x19TRON Signed Message:\n";
pub const BIP44_PATH: u32 = 195;

#[wasm_bindgen]
impl TRX {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BaseChain {
            name: "Tron",
            symbol: "TRX",
            precision: 6,
            node_url: "https://api.trongrid.io",
        }
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Secp256k1KeyPair::random(&mut rng);
        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        let kp = Secp256k1KeyPair::new_from_mnemonic_phrase_with_path(
            mnemonic,
            path,
            password.as_deref(),
        )?;

        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        Ok(address::Address::from_keypair(kp).to_string())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(index: u32) -> Result<String, Error> {
        Ok(format!("m/44'/{}'/{}'/0/0", BIP44_PATH, index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let raw = keypair.sign_digest(digest);
        Ok(raw)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<(), Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Tron(trx_tx)) => {
                let mut new_tx = trx_tx.clone();
                let raw = trx_tx.raw_data.unwrap();
                let bytes = kos_proto::write_message(raw);
                let digest = TRX::hash(&bytes)?;
                let sig = TRX::sign_digest(digest.as_slice(), keypair)?;

                new_tx.signature.push(sig);
                let result = Transaction {
                    chain: tx.chain,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Tron(new_tx)),
                };

                Ok(result)
            }
            _ => return Err(Error::InvalidMessage("not a klever transaction")),
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// Append prefix and hash the message
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let digest = hasher.finalize();
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        TRX::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = TRX::message_hash(message)?;
        TRX::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<(), Error> {
        let m = TRX::message_hash(message)?;
        TRX::verify_digest(&m, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    /// Get balance of address and token
    /// If token is None, it will return balance of native token
    /// If token is Some, it will return balance of token
    /// If node_url is None, it will use default node url
    pub async fn get_balance(
        addr: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| TRX::base_chain().node_url.to_string());
        let acc_address = address::Address::from_str(addr)?;

        // check if TRC20 -> trigger contract instead todo!()
        let acc = requests::get_account(node.as_str(), &acc_address.to_hex_address()).await?;

        Ok(match token {
            Some(key) if key != "TRX" => match acc.asset_v2.get(&key) {
                Some(value) => BigNumber::from(*value),
                None => BigNumber::from(0),
            },
            _ => BigNumber::from(acc.balance),
        })
    }

    /// create a send transaction network
    #[wasm_bindgen(js_name = "send")]
    pub async fn send(
        _sender: String,
        _receiver: String,
        _amount: BigNumber,
        _options: Option<models::SendOptions>,
        _node_url: Option<String>,
    ) -> Result<crate::models::Transaction, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        _data: models::Transaction,
        _node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use super::*;
    use hex::FromHex;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28";
    const DEFAULT_ADDRESS: &str = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_mnemonic() {
        let path = TRX::get_path(0).unwrap();
        let kp = TRX::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", &path, None).unwrap();
        let address = TRX::get_address_from_keypair(&kp).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_address_from_private_key() {
        let address = TRX::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_get_balance() {
        let balance = tokio_test::block_on(TRX::get_balance(
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
            Some("TRX".to_string()),
            None,
        ))
        .unwrap();
        println!("balance: {}", balance.to_string());

        assert_eq!("2", balance.to_string());
    }
}
