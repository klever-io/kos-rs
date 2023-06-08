pub mod address;
pub mod transaction;

use crate::chain::BaseChain;
use crate::models::{self, BroadcastResult, Transaction, TransactionRaw};
use kos_crypto::keypair::KeyPair;
use kos_crypto::secp256k1::Secp256k1KeyPair;
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct ETH {
    pub chain_id: u64,
}

pub const SIGN_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub const BIP44_PATH: u32 = 60;

#[wasm_bindgen]
impl ETH {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BaseChain {
            name: "Ethereum",
            symbol: "ETH",
            precision: 18,
            node_url: "NONE",
            chain_code: 3,
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
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<(), Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Ethereum(eth_tx)) => {
                let mut new_tx = eth_tx.clone();
                let bytes = eth_tx.encode()?;
                let digest = ETH::hash(&bytes)?;
                let sig = ETH::sign_digest(digest.as_slice(), keypair)?;

                new_tx.signature = Some(RecoverableSignature::from_compact(
                    &sig[..64],
                    RecoveryId::from_i32(sig[64] as i32)?,
                )?);
                let result = Transaction {
                    chain: tx.chain,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Ethereum(new_tx)),
                };

                Ok(result)
            }
            _ => return Err(Error::InvalidMessage("not a ethereum transaction")),
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
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        ETH::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = ETH::message_hash(message)?;
        ETH::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<(), Error> {
        let m = ETH::message_hash(message)?;
        ETH::verify_digest(&m, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        _address: &str,
        _token: Option<String>,
        _node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        todo!()
    }

    pub async fn send(
        _sender: String,
        _receiver: String,
        _amount: BigNumber,
        _options: Option<models::SendOptions>,
        _node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        _data: crate::models::Transaction,
        _node_url: Option<String>,
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
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
    const DEFAULT_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const DEFAULT_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_private_key() {
        let address = ETH::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_validate_tron_bip44() {
        let v = vec![
            (0, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            (1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            (2, "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"),
            (3, "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E"),
            (4, "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA"),
        ];

        for (index, expected_addr) in v {
            let path = ETH::get_path(index).unwrap();
            let kp = ETH::keypair_from_mnemonic(DEFAULT_MNEMONIC, &path, None).unwrap();
            let addr = ETH::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }
}
