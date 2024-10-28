use super::{polkadot, SubstrateTransaction};

use crate::chain::BaseChain;
use crate::models::{self, BroadcastResult, Transaction, TransactionRaw};
use crate::models::{PathOptions, SendOptions};

use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use super::DOT;
use kos_types::hash::Hash;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct AVAIL {}

const SS58_PREFIX: u16 = 42;

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Avail",
    symbol: "AVAIL",
    precision: 18,
    chain_code: 62,
};

#[wasm_bindgen]
impl AVAIL {
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
        DOT::sign(tx, keypair)
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
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("AVAIL"));
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
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("AVAIL"));
        let result = DOT::broadcast(tx, Some(node)).await?;
        Ok(BroadcastResult::new(result.tx))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        DOT::validate_address(address, option)
    }

    pub fn tx_from_json(raw: &str) -> Result<models::Transaction, Error> {
        let tx = SubstrateTransaction::from_json(raw)?;

        Ok(Transaction {
            chain: crate::chain::Chain::AVAIL,
            sender: tx.clone().address,
            hash: Hash::default(),
            data: Some(TransactionRaw::Substrate(tx.clone())),
            signature: tx.signature,
        })
    }
}
#[cfg(test)]
mod tests {
    use crate::chain::Chain;
    use crate::chains::AVAIL;

    #[test]
    fn test_keypair_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = AVAIL::get_path(&super::PathOptions {
            index: 0,
            is_legacy: None,
        })
        .unwrap();
        let kp = AVAIL::keypair_from_mnemonic(mnemonic, &path, None).unwrap();
        let address = AVAIL::get_address_from_keypair(&kp).unwrap();
        assert_eq!(address, "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH");
    }

    #[test]
    fn test_get_path() {
        let path = AVAIL::get_path(&super::PathOptions {
            index: 1,
            is_legacy: None,
        })
        .unwrap();

        assert_eq!(path, "//0");
    }

    #[test]
    fn test_validate_address() {
        let address = "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1";
        let valid = AVAIL::validate_address(address, None).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_digest() {
        let kp = AVAIL::keypair_from_bytes(&[0u8; 32]).unwrap();
        let digest = String::from("hello").into_bytes();
        let signature = AVAIL::sign_digest(&digest, &kp).unwrap();
        assert_eq!(signature.len(), 64);

        let address = AVAIL::get_address_from_keypair(&kp).unwrap();
        let valid = AVAIL::verify_digest(&digest, &signature, &address).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_extrinsic_payload() {
        let json_data = r#"
          {
            "appId": 0,
            "specVersion": "0x00000027",
            "transactionVersion": "0x00000001",
            "address": "5H9CP2zS3ufvZLcxc3rB2Go6ujr6c1FyE4AjFk7E19vCZyK4",
            "assetId": null,
            "blockHash": "0xc2ff0603e37eb015106f24a4f6eb3fbca3aef2e21cd19c654f88853337bf4d7d",
            "blockNumber": "0x0007ab6d",
            "era": "0xd400",
            "genesisHash": "0xb91746b45e0346cc2f815a520b9c6cb4d5c0902af848db0a80f85932d2e8276a",
            "metadataHash": null,
            "method": "0x060300e09a2af0eb7f9adcc71e489111ff691cf8430e6f1d86969156a822218217411500",
            "mode": 0,
            "nonce": "0x00000010",
            "signedExtensions": [
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeTransactionPayment",
                "CheckAppId"
            ],
            "tip": "0x00000000000000000000000000000000",
            "version": 4,
            "withSignedTransaction": true
        }"#;

        let transaction = AVAIL::tx_from_json(json_data).unwrap();

        let kp = AVAIL::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "//0", None).unwrap();

        let signed = AVAIL::sign(transaction, &kp).unwrap();

        assert_eq!(signed.get_signature().unwrap().len(), 130);
        assert_eq!(signed.chain, Chain::AVAIL);
    }
}
