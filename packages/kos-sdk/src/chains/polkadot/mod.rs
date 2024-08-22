mod address;

use std::str::FromStr;

use crate::{
    chain::{self, BaseChain},
    models::{PathOptions, Transaction, TransactionRaw},
};
use kos_crypto::{keypair::KeyPair};
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;

use wasm_bindgen::prelude::*;
use kos_crypto::sr25519::Sr25519KeyPair;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct DOT {}

pub const BIP44_PATH: u32 = 195;
pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Polkadot",
    symbol: "DOT",
    precision: 10,
    chain_code: 21,
};

#[wasm_bindgen]
impl DOT {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }


    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        // copy to fixed length array
        let mut pk_slice = [0u8; 32];
        pk_slice.copy_from_slice(private_key);

        let kp = Sr25519KeyPair::new(pk_slice);
        Ok(KeyPair::new_sr25519(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        let kp = Sr25519KeyPair::new_from_mnemonic_phrase_with_path(
            mnemonic,
            path,
            password.as_deref(),
        )?;

        Ok(KeyPair::new_sr25519(kp))
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        Ok(address::Address::from_keypair(kp).to_string())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(options: &PathOptions) -> Result<String, Error> {
        let index = options.index;

        Ok(format!("m/44'/{}'/0'/0/{}", BIP44_PATH, index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let raw = keypair.sign_digest(digest);
        Ok(raw)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<bool, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Tron(trx_tx)) => {
                let mut new_tx = trx_tx.clone();
                let digest = Vec::new();
                let sig = Vec::new();

                new_tx.signature.push(sig);
                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Tron(new_tx)),
                };

                Ok(result)
            }
            _ => Err(Error::InvalidMessage("not a tron transaction".to_string())),
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = kos_crypto::hash::sha256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        addr: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        Ok(BigNumber::from(0))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        addr: &str,
        _option: Option<crate::models::AddressOptions>,
    ) -> Result<bool, Error> {
        Ok(true)
    }
}

// Test keypair from mnemonic
#[cfg(test)]
mod tests {

    #[test]
    fn test_keypair_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/44'/195'/0'/0/0";
        let kp = super::DOT::keypair_from_mnemonic(mnemonic, path, None).unwrap();
        let address = super::DOT::get_address_from_keypair(&kp).unwrap();
        assert_eq!(address, "");
    }

}

