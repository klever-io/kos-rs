pub mod address;
pub mod models;
pub mod requests;
use crate::{
    chain::BaseChain,
    models::{BroadcastResult, Transaction, TransactionRaw},
};
use kos_crypto::{ed25519::Ed25519KeyPair, keypair::KeyPair};
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use std::todo;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen()]
pub struct KLV {}

pub const SIGN_PREFIX: &[u8; 24] = b"\x17Klever Signed Message:\n";
pub const BIP44_PATH: u32 = 690;
// todo!() check if needed
// pub const BIP44_PATH_TESTNET: u32 = 620;

#[wasm_bindgen]
impl KLV {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BaseChain {
            name: "Klever",
            symbol: "KLV",
            precision: 6,
            chain_code: 38,
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
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Klever(klv_tx)) => {
                let mut new_tx = klv_tx.clone();
                let digest = KLV::hash_transaction(&klv_tx)?;
                let sig = KLV::sign_digest(digest.as_slice(), keypair)?;

                new_tx.signature.push(sig);
                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Klever(new_tx)),
                };

                Ok(result)
            }
            _ => {
                return Err(Error::InvalidMessage(
                    "not a klever transaction".to_string(),
                ))
            }
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
            receiver: receiver,
            amount: amount.to_i64(),
            kda: options.kda.clone(),
            kda_royalties: options.kda_royalties,
        };

        requests::make_request(sender, contract, &options, node.as_str()).await
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
        let klv_tx: kos_proto::klever::Transaction = serde_json::from_str(
            "{\"RawData\":{\"Nonce\":13,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBIDS0xWGAo=\"}}],\"KAppFee\":500000,\"BandwidthFee\":1000000,\"Version\":1,\"ChainID\":\"MTAwNDIw\"},\"Signature\":[\"O7C2MjTUMauWl8kfeJjgwDnFLkiDqY2U23s6AWzTstut63FnZeKC3EcxY0DiAgzf5PQ1+jeC2dIx3+pP7BHlBQ==\"]}",
        ).unwrap();

        let to_broadcast = crate::models::Transaction {
            chain: crate::chain::Chain::KLV,
            sender: "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
            hash: Hash::new("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            data: Some(TransactionRaw::Klever(klv_tx)),
        };

        let result = tokio_test::block_on(KLV::broadcast(
            to_broadcast,
            Some("https://node.testnet.klever.finance".to_string()),
        ));

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("lowerNonceInTx: true"))
    }

    #[test]
    fn test_send() {
        let result = tokio_test::block_on(KLV::send(
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm".to_string(),
            BigNumber::from(10),
            None,
            Some("https://node.testnet.klever.finance".to_string()),
        ));

        assert!(result.is_ok());
        match result.unwrap().data {
            Some(TransactionRaw::Klever(tx)) => {
                let raw = &tx.raw_data.unwrap();
                assert!(raw.nonce > 0);
                assert_eq!(raw.contract.len(), 1);
                let c: kos_proto::klever::TransferContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();

                assert_eq!(c.amount, 10);
            }
            _ => assert!(false),
        }
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
