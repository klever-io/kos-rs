pub mod address;
pub mod models;
pub mod requests;
use crate::{
    chain::BaseChain,
    models::{AddressOptions, BroadcastResult, PathOptions, Transaction, TransactionRaw},
};
use kos_crypto::{ed25519::Ed25519KeyPair, keypair::KeyPair};
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use pbjson::private::base64;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen()]
pub struct KLV {}

pub const SIGN_PREFIX: &[u8; 24] = b"\x17Klever Signed Message:\n";
pub const BIP44_PATH: u32 = 690;
pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Klever",
    symbol: "KLV",
    precision: 6,
    chain_code: 38,
};

#[wasm_bindgen]
impl KLV {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::random(&mut rng);
        Ok(KeyPair::new_ed25519(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        // copy to fixed length array
        let mut pk_slice = [0u8; 32];
        pk_slice.copy_from_slice(private_key);

        let kp = Ed25519KeyPair::new(pk_slice);
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
        Ok(address::Address::from_keypair(keypair).to_string())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(options: &PathOptions) -> Result<String, Error> {
        Ok(format!("m/44'/{}'/0'/0'/{}'", BIP44_PATH, options.index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let sig = keypair.sign_digest(digest);
        Ok(sig)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], address: &str) -> Result<bool, Error> {
        let addr = address::Address::from_str(address)?;
        let kp = Ed25519KeyPair::default();

        if kp.verify_digest(digest, signature, &addr.public_key()) {
            Ok(true)
        } else {
            Err(Error::InvalidSignature("message verification fail"))
        }
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Klever(klv_tx)) => {
                let mut new_tx = klv_tx.clone();
                let digest = KLV::hash_transaction(&klv_tx)?;
                let sig = KLV::sign_digest(digest.as_slice(), keypair)?;

                let signature = base64::encode(sig.clone());

                new_tx.signature.push(sig);
                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Klever(new_tx)),
                    signature: Some(signature),
                };

                Ok(result)
            }
            _ => Err(Error::InvalidMessage(
                "not a klever transaction".to_string(),
            )),
        }
    }

    fn hash_transaction(tx: &kos_proto::klever::Transaction) -> Result<Vec<u8>, Error> {
        if let Some(raw_data) = &tx.raw_data {
            let bytes = kos_proto::write_message(raw_data);
            KLV::hash(&bytes)
        } else {
            Err(Error::InvalidTransaction("klv raw".to_string()))
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = kos_crypto::hash::blake2b256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        let digest = kos_crypto::hash::keccak256(&to_sign);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = KLV::message_hash(message)?;
        KLV::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<bool, Error> {
        let m = KLV::message_hash(message)?;
        KLV::verify_digest(&m, signature, address)
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
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("KLV"));
        let acc = requests::get_account(node.as_str(), address).await?;

        Ok(match token {
            Some(key) if key != "KLV" => match acc.assets.unwrap().get(&key) {
                Some(asset) => BigNumber::from(asset.balance),
                None => BigNumber::from(0),
            },
            _ => BigNumber::from(acc.balance.unwrap_or(0)),
        })
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("KLV"));
        let raw = tx
            .data
            .clone()
            .ok_or_else(|| Error::ReqwestError("Missing transaction data".into()))?;

        let result = requests::broadcast(node.as_str(), raw.try_into()?).await?;

        match result.get("data").and_then(|v| v.as_object()) {
            Some(v) => {
                let tx_hash_str = v
                    .get("txHash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::ReqwestError("Missing transaction hash".into()))?;

                let tx_hash = Hash::new(tx_hash_str)?;

                Ok(BroadcastResult::new(crate::models::Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: tx_hash,
                    data: tx.data,
                    signature: None,
                }))
            }
            None => match result.get("error") {
                Some(err) => Err(Error::ReqwestError(err.to_string())),
                None => Err(Error::ReqwestError("Unknown error".into())),
            },
        }
    }

    fn get_options(options: Option<crate::models::SendOptions>) -> kos_proto::options::KLVOptions {
        match options.and_then(|opt| opt.data) {
            Some(crate::models::Options::Klever(op)) => op,
            _ => kos_proto::options::KLVOptions::default(),
        }
    }

    /// create a send transaction network
    #[wasm_bindgen(js_name = "send")]
    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<crate::models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<crate::models::Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("KLV"));
        let options = KLV::get_options(options);

        let contract = models::TransferTXRequest {
            receiver,
            amount: amount.to_i64(),
            kda: options.kda.clone(),
            kda_royalties: options.kda_royalties,
        };

        requests::make_request(sender, contract, &options, node.as_str()).await
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        _options: Option<AddressOptions>,
    ) -> Result<bool, Error> {
        let addr = address::Address::from_str(address);
        if addr.is_err() {
            return Ok(false);
        }

        if addr.unwrap().to_string() == address {
            return Ok(true);
        }

        Ok(false)
    }
}

#[wasm_bindgen]
impl KLV {
    /// import raw TX rom JSValue to Transaction model
    #[wasm_bindgen(js_name = "txFromRaw")]
    pub fn tx_from_raw(raw: &str) -> Result<crate::models::Transaction, Error> {
        // build expected send result
        let tx: kos_proto::klever::Transaction = serde_json::from_str(raw)?;

        // unwrap raw_data
        let data = tx
            .raw_data
            .clone()
            .ok_or_else(|| Error::InvalidTransaction("no raw TX found".to_string()))?;

        let sender = address::Address::from_bytes(&data.sender);
        let digest = KLV::hash_transaction(&tx)?;
        let signature = base64::encode(tx.signature.first().unwrap().clone());

        Ok(crate::models::Transaction {
            chain: crate::chain::Chain::KLV,
            sender: sender.to_string(),
            hash: Hash::from_slice(&digest)?,
            data: Some(TransactionRaw::Klever(tx)),
            signature: Some(signature),
        })
    }
}

#[cfg(test)]
mod klever_test;
