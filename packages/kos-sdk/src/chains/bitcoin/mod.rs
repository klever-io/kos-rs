mod requests;
pub mod transaction;

use crate::chain::{BaseChain, Chain};
use crate::models::{self, BroadcastResult, Transaction, TransactionRaw};

use kos_crypto::{keypair::KeyPair, secp256k1::Secp256k1KeyPair};
use kos_proto::options::BTCOptions;
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use bitcoin::{network::constants::Magic, Address, Network};

use std::{ops::Add, str::FromStr};
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

const DEFAULT_NETWORK: Network = Network::Bitcoin;

pub fn get_network(option: &BTCOptions) -> Result<Network, Error> {
    match option.network.clone() {
        Some(hex_magic) => {
            let magic_bytes = hex::decode(hex_magic)?;
            if magic_bytes.len() != 4 {
                return Err(Error::UnsupportedChain("invalid magic for network length"));
            }

            let array: [u8; 4] = [
                magic_bytes[0],
                magic_bytes[1],
                magic_bytes[2],
                magic_bytes[3],
            ];
            let magic = Magic::from_bytes(array);

            Network::from_magic(magic).ok_or(Error::UnsupportedChain("invalid magic for network"))
        }
        _ => Ok(DEFAULT_NETWORK),
    }
}

fn get_options(options: Option<crate::models::SendOptions>) -> BTCOptions {
    match options.and_then(|opt| opt.data) {
        Some(crate::models::Options::Bitcoin(op)) => op,
        _ => BTCOptions::default(),
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

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        // copy to fixed length array
        let mut pk_slice = [0u8; 32];
        pk_slice.copy_from_slice(private_key);

        let kp = Secp256k1KeyPair::new(pk_slice).set_compressed(true);
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
        let address = BTC::get_address(kp, DEFAULT_NETWORK)?;
        Ok(address.to_string())
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
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<bool, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    /// P2WPKH address is used as the signature address.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            // get bitcoin transaction from raw
            Some(TransactionRaw::Bitcoin(btc_tx)) => {
                let mut btc_tx = btc_tx;

                // sign tx
                btc_tx.sign(keypair)?;

                // redeem script
                btc_tx.finalize()?;

                Ok(Transaction {
                    hash: btc_tx.txid_hash()?,
                    data: Some(TransactionRaw::Bitcoin(btc_tx)),
                    ..tx
                })
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
    ) -> Result<bool, Error> {
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

    fn get_receiver(
        receiver: String,
        amount: &BigNumber,
        network: Network,
    ) -> Result<(Address, BigNumber), Error> {
        let addr =
            Address::from_str(&receiver).map_err(|e| Error::InvalidAddress(e.to_string()))?;
        Ok((
            addr.require_network(network)
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

        let network = get_network(&options)?;

        let mut total_amount = amount.clone();

        let mut receivers: Vec<(Address, BigNumber)> = Vec::new();
        if !receiver.is_empty() {
            receivers.push(Self::get_receiver(receiver, &amount, network)?);
        } else {
            // check if amount is provided without receiver
            if !amount.is_zero() {
                return Err(Error::InvalidTransaction(format!(
                    "receiver is required for amount {}",
                    amount.to_string()
                )));
            }
        }
        // add outputs from options
        for output in options.receivers() {
            receivers.push(Self::get_receiver(output.0, &output.1, network)?);
            total_amount = total_amount.add(output.1);
        }

        let sender_address = Address::from_str(&sender.clone())
            .map_err(|e| Error::InvalidAddress(e.to_string()))?
            .require_network(network)
            .map_err(|e| Error::InvalidAddress(e.to_string()))?;

        let change_address =
            Address::from_str(&options.change_address.clone().unwrap_or(sender.clone()))
                .map_err(|e| Error::InvalidAddress(e.to_string()))?
                .require_network(network)
                .map_err(|e| Error::InvalidAddress(e.to_string()))?;

        // get utoxs
        let sender_utxos =
            requests::select_utxos(&node, &sender, &total_amount, 1, 1, 10, false, false).await?;

        // create transaction
        let tx = transaction::create_transaction(
            sender_address,
            sender_utxos,
            receivers,
            change_address,
            &options,
        )?;

        Ok(crate::models::Transaction {
            chain: Chain::BTC,
            sender,
            hash: Hash::new(&tx.txid().to_string())?,
            data: Some(TransactionRaw::Bitcoin(tx)),
        })
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("BTC"));

        match &tx.data {
            Some(TransactionRaw::Bitcoin(btc_tx)) => {
                let txid = requests::broadcast(&node, &btc_tx.btc_serialize_hex()).await?;
                // check if tx hash is same as txid
                if btc_tx.txid() != txid {
                    return Err(Error::InvalidTransaction(format!(
                        "invalid transaction hash: {}/{}",
                        txid,
                        btc_tx.txid()
                    )));
                }
                Ok(BroadcastResult { tx })
            }
            _ => Err(Error::InvalidTransaction(
                "not a bitcoin transaction".to_string(),
            )),
        }
    }

    fn decode_magic(hex_magic: String) -> Result<Network, Error> {
        let magic_bytes = hex::decode(hex_magic)?;
        if magic_bytes.len() != 4 {
            return Err(Error::UnsupportedChain("invalid magic for network length"));
        }

        let array: [u8; 4] = [
            magic_bytes[0],
            magic_bytes[1],
            magic_bytes[2],
            magic_bytes[3],
        ];
        let magic = Magic::from_bytes(array);

        let network = Network::from_magic(magic)
            .ok_or(Error::UnsupportedChain("invalid magic for network"))?;

        Ok(network)
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        options: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        let addr = Address::from_str(address);
        if addr.is_err() {
            return Ok(false);
        }

        let addr = addr.unwrap();

        // get network from options
        let network = match options {
            Some(opt) => match opt.network {
                Some(hex_magic) => BTC::decode_magic(hex_magic)?,
                _ => DEFAULT_NETWORK,
            },
            _ => DEFAULT_NETWORK,
        };

        Ok(addr.is_valid_for_network(network))
    }
}

impl BTC {
    #[inline]
    pub fn get_address(kp: &KeyPair, network: Network) -> Result<Address, Error> {
        let pubkey = BTC::get_pubkey(&kp.public_key())?;

        Address::p2wpkh(&pubkey, network).map_err(|e| Error::InvalidAddress(e.to_string()))
    }

    #[inline]
    pub fn get_pubkey(data: &[u8]) -> Result<bitcoin::PublicKey, Error> {
        bitcoin::PublicKey::from_slice(data)
            .map_err(|e| Error::InvalidPublicKey(format!("Invalid public key: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{FromHex, ToHex};
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
    fn test_address_from_private_key_bytes() {
        // convert hex to [u8]
        let pk_bytes = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = BTC::keypair_from_bytes(pk_bytes.as_ref()).unwrap();
        let address = BTC::get_address_from_keypair(&kp).unwrap();

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
    fn test_send_and_sign() {
        let btc_address_sender = "tb1q09hyefvam4x5hrnnavx6sphv797f0l5xcqt7cl";
        let btc_address_receiver = "tb1qgg29y2z8xsvav65j5kx2pztqff4g2ctn6a4x0u";
        let node = "https://tbtc1.trezor.io";

        let testnet_magic = "0b110907";

        let option = models::SendOptions {
            data: Some(models::Options::Bitcoin(BTCOptions {
                sats_per_bytes: Some(1),
                network: Some(testnet_magic.to_string()),
                ..Default::default()
            })),
        };

        let send_tx = tokio_test::block_on(BTC::send(
            btc_address_sender.to_string(),
            btc_address_receiver.to_string(),
            BigNumber::from(1000),
            Some(option),
            Some(node.to_string()),
        ))
        .unwrap();

        let sign_tx = BTC::sign(send_tx, &get_default_secret()).unwrap();

        let tx = match sign_tx.data.unwrap() {
            TransactionRaw::Bitcoin(tx) => tx,
            _ => panic!("invalid transaction"),
        };

        assert!(tx.total_send.to_u64() == 1000);
        assert!(tx.fee.to_u64() == 226);
        // let _ = tokio_test::block_on(BTC::broadcast(sign_tx, Some(node.to_string()))).unwrap();
    }

    #[test]
    fn test_validate_address_ok() {
        let list = [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
        ];

        for addr in list.iter() {
            let valid = BTC::validate_address(addr, None).unwrap();
            assert_eq!(valid, true, "address {} should be valid", addr);
        }

        // network mainnet
        for addr in list.iter() {
            let valid = BTC::validate_address(
                addr,
                Some(models::AddressOptions::new(
                    Some(Network::Bitcoin.magic().encode_hex()),
                    None,
                    None,
                )),
            )
            .unwrap();
            assert_eq!(valid, true, "address {} should be valid", addr);
        }
    }

    #[test]
    fn test_validate_address_fail() {
        let list = [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
        ];

        // wrong network
        for addr in list.iter() {
            let valid = BTC::validate_address(
                addr,
                Some(models::AddressOptions::new(
                    Some(Network::Testnet.magic().encode_hex()),
                    None,
                    None,
                )),
            )
            .unwrap();
            assert_eq!(valid, false, "address {} should be invalid", addr);
        }

        let list = [
            "qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",     // no prefix
            "ltc1qz9vvmr3q2s6m4drd9y9plzs0l38u9z4p96wwxz", // wrong prefix
            "BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN",
        ];

        for addr in list.iter() {
            let valid = BTC::validate_address(addr, None).unwrap();
            assert_eq!(valid, false, "address {} should be invalid", addr);
        }
    }
}
