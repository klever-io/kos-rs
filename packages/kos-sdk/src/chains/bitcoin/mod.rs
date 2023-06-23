mod requests;
pub mod transaction;

use crate::chain::{BaseChain, Chain};
use crate::models::{self, BroadcastResult, Transaction, TransactionRaw};

use kos_crypto::{keypair::KeyPair, secp256k1::Secp256k1KeyPair};
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use bitcoin::{Address, Network};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct BTC {}

pub const SIGN_PREFIX: &[u8; 25] = b"\x18Bitcoin Signed Message:\n";
pub const BIP44_PATH: u32 = 0;

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Bitcoin",
    symbol: "BTC",
    precision: 8,
    chain_code: 2,
};

pub fn get_network() -> Network {
    Network::Bitcoin
}

fn get_options(options: Option<crate::models::SendOptions>) -> kos_proto::options::BTCOptions {
    match options.and_then(|opt| opt.data) {
        Some(crate::models::Options::Bitcoin(op)) => op,
        _ => kos_proto::options::BTCOptions::default(),
    }
}

#[wasm_bindgen]
impl BTC {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Secp256k1KeyPair::random(&mut rng).set_compressed(true);
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
        )?
        .set_compressed(true);

        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        let pubkey = bitcoin::PublicKey::from_slice(&kp.public_key()).map_err(|e| {
            Error::InvalidPublicKey(format!("Invalid public key: {}", e.to_string()))
        })?;

        Address::p2wpkh(&pubkey, get_network())
            .map(|a| a.to_string())
            .map_err(|e| Error::InvalidAddress(e.to_string()).into())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(index: u32) -> Result<String, Error> {
        Ok(format!("m/84'/{}'/0'/0/{}", BIP44_PATH, index))
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
            Some(TransactionRaw::Bitcoin(btc_tx)) => {
                todo!()
            }
            _ => Err(Error::InvalidMessage(
                "not a bitcoin transaction".to_string(),
            )),
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = kos_crypto::hash::keccak256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        BTC::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = BTC::message_hash(message)?;
        BTC::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<(), Error> {
        let m = BTC::message_hash(message)?;
        BTC::verify_digest(&m, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        address: &str,
        _token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("BTC"));
        requests::balance(&node, address, 0).await
    }

    fn get_receiver(receiver: String, amount: &BigNumber) -> Result<(Address, BigNumber), Error> {
        let addr =
            Address::from_str(&receiver).map_err(|e| Error::InvalidAddress(e.to_string()))?;
        Ok((
            addr.require_network(get_network())
                .map_err(|e| Error::InvalidAddress(e.to_string()))?,
            amount.clone(),
        ))
    }

    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("BTC"));
        let options = get_options(options);

        let mut total_amount = amount.clone();

        let mut receivers: Vec<(Address, BigNumber)> = Vec::new();
        if !receiver.is_empty() {
            receivers.push(Self::get_receiver(receiver, &amount)?);
        }
        // add outputs from options
        for output in options.receivers.unwrap_or(vec![]) {
            receivers.push(Self::get_receiver(output.0, &output.1)?);
            total_amount = total_amount.add(&output.1);
        }

        // todo!() compute fee
        let sats_per_bytes = options.stats_per_bytes.unwrap_or_default();

        let change_address = Address::from_str(&options.change_address.unwrap_or(sender.clone()))
            .map_err(|e| Error::InvalidAddress(e.to_string()))?
            .require_network(get_network())
            .map_err(|e| Error::InvalidAddress(e.to_string()))?;

        // get utoxs
        let sender_utxos =
            requests::select_utxos(&node, &sender, &total_amount, 1, 1, 10, false, false).await?;

        // create transaction
        let tx = transaction::create_transaction(
            sender_utxos,
            receivers,
            sats_per_bytes,
            change_address,
            options.dust_value,
        )?;

        Ok(crate::models::Transaction {
            chain: Chain::BTC,
            sender: sender,
            hash: Hash::new(&tx.ntxid().to_string())?,
            data: Some(TransactionRaw::Bitcoin(tx)),
        })
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";
    const DEFAULT_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into()).set_compressed(true);
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_private_key() {
        let address = BTC::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_validate_bip44() {
        let v = vec![
            (0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            (1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
            (2, "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z"),
            (3, "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3"),
            (4, "bc1qm97vqzgj934vnaq9s53ynkyf9dgr05rargr04n"),
        ];

        for (index, expected_addr) in v {
            let path = BTC::get_path(index).unwrap();
            let kp = BTC::keypair_from_mnemonic(DEFAULT_MNEMONIC, &path, None).unwrap();
            let addr = BTC::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }

    #[test]
    fn test_get_balance() {
        let balance = tokio_test::block_on(BTC::get_balance(
            "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
            None,
            None,
        ))
        .unwrap();

        assert!(balance.to_i64() > 100);
    }

    #[test]
    fn test_send_end_sign() {
        todo!()
    }
}
