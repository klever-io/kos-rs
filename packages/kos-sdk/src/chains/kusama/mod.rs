use super::{polkadot, DOTTransaction};

use crate::chain::{BaseChain, Chain};
use crate::models::{self, BroadcastResult, TransactionRaw};
use crate::models::{PathOptions, SendOptions};

use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use super::DOT;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct KSM {}

const SS58_PREFIX: u16 = 2;

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Kusama",
    symbol: "KSM",
    precision: 12,
    chain_code: 27,
};

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Transaction {
    pub ksm: DOTTransaction,
}

fn convert_transaction(tx: models::Transaction) -> Result<models::Transaction, Error> {
    match tx.data.clone() {
        Some(TransactionRaw::Kusama(tx_kusama)) => {
            Ok(tx.new_data(Chain::KSM, TransactionRaw::Polkadot(tx_kusama.ksm)))
        }
        Some(TransactionRaw::Polkadot(tx_ksm)) => Ok(tx.new_data(
            Chain::KSM,
            TransactionRaw::Kusama(Transaction { ksm: tx_ksm }),
        )),
        _ => Err(Error::InvalidTransaction(
            "Invalid Transaction Type".to_string(),
        )),
    }
}

#[wasm_bindgen]
impl KSM {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        DOT::random()
    }

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        DOT::keypair_from_bytes(private_key)
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        DOT::keypair_from_mnemonic(mnemonic, path, password)
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        Ok(polkadot::address::Address::from_keypair(kp).to_ss58check(SS58_PREFIX))
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(options: &PathOptions) -> Result<String, Error> {
        DOT::get_path(options)
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        DOT::sign_digest(digest, keypair)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], address: &str) -> Result<bool, Error> {
        DOT::verify_digest(digest, signature, address)
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: models::Transaction, keypair: &KeyPair) -> Result<models::Transaction, Error> {
        let result = DOT::sign(convert_transaction(tx)?, keypair);

        // convert back to polygon tx enum
        convert_transaction(result?)
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        DOT::hash(message)
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        DOT::message_hash(message)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        DOT::sign_message(message, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<bool, Error> {
        DOT::verify_message_signature(message, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("KSM"));
        DOT::get_balance(address, token, Some(node)).await
    }

    pub async fn send(
        _sender: String,
        _receiver: String,
        _amount: BigNumber,
        _options: Option<SendOptions>,
        _node_url: Option<String>,
    ) -> Result<models::Transaction, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("KSM"));
        let result = DOT::broadcast(tx, Some(node)).await?;
        Ok(BroadcastResult::new(convert_transaction(result.tx)?))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        DOT::validate_address(address, option)
    }

    pub fn tx_from_json(raw: &str) -> Result<models::Transaction, Error> {
        let transaction = DOT::tx_from_json(raw)?;
        Ok(convert_transaction(transaction)?)
    }
}
#[cfg(test)]
mod tests {
    use crate::chain::Chain;
    use crate::chains::KSM;

    #[test]
    fn test_keypair_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = KSM::get_path(&super::PathOptions {
            index: 0,
            is_legacy: None,
        })
        .unwrap();
        let kp = KSM::keypair_from_mnemonic(mnemonic, &path, None).unwrap();
        let address = KSM::get_address_from_keypair(&kp).unwrap();
        assert_eq!(address, "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1");
    }

    #[test]
    fn test_get_path() {
        let path = KSM::get_path(&super::PathOptions {
            index: 1,
            is_legacy: None,
        })
        .unwrap();

        assert_eq!(path, "//0");
    }

    #[test]
    fn test_validate_address() {
        let address = "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1";
        let valid = KSM::validate_address(address, None).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_digest() {
        let kp = KSM::keypair_from_bytes(&[0u8; 32]).unwrap();
        let digest = String::from("hello").into_bytes();
        let signature = KSM::sign_digest(&digest, &kp).unwrap();
        assert_eq!(signature.len(), 64);

        let address = KSM::get_address_from_keypair(&kp).unwrap();
        let valid = KSM::verify_digest(&digest, &signature, &address).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_extrinsic_payload() {
        let json_data = r#"
                {
                "specVersion": "0x000f4dfb",
                "transactionVersion": "0x0000001a",
                "address": "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1",
                "assetId": null,
                "blockHash": "0x5e8ad2dc466562ea590e2e05b81ee851ca55bce18caf0407f4bb2daf8e0beaf9",
                "blockNumber": "0x01608e70",
                "era": "0x0503",
                "genesisHash": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                "metadataHash": null,
                "method": "0x050300a653ae79665565ba7fc682c385b3c038c2091ab6d6053355b9950a108ac48b0600",
                "mode": 0,
                "nonce": "0x00000000",
                "signedExtensions": [
                    "CheckNonZeroSender",
                    "CheckSpecVersion",
                    "CheckTxVersion",
                    "CheckGenesis",
                    "CheckMortality",
                    "CheckNonce",
                    "CheckWeight",
                    "ChargeTransactionPayment",
                    "PrevalidateAttests",
                    "CheckMetadataHash"
                ],
                "tip": "0x00000000000000000000000000000000",
                "version": 4,
                "withSignedTransaction": true
            }"#;

        let transaction = KSM::tx_from_json(json_data).unwrap();

        let kp = KSM::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "//0", None).unwrap();

        let signed = KSM::sign(transaction, &kp).unwrap();

        assert_eq!(signed.get_signature().unwrap().len(), 130);
        assert_eq!(signed.chain, Chain::KSM);
    }
}
