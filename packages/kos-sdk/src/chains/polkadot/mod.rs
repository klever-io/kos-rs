mod address;
pub mod transaction;

use crate::chains::DOTTransaction;
use crate::models::BroadcastResult;
use crate::{
    chain::{self, BaseChain},
    models,
    models::{PathOptions, Transaction, TransactionRaw},
};
use base64::{engine::general_purpose as b64_engine, Engine};
use kos_crypto::keypair::KeyPair;
use kos_crypto::sr25519::Sr25519KeyPair;
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use std::str::FromStr;
use subxt::client::OfflineClientT;
use subxt::ext::codec::Decode;
use subxt::tx::SubmittableExtrinsic;
use subxt::utils::H256;
use subxt::{Metadata, OfflineClient, PolkadotConfig};
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct DOT {}

pub const SIGN_PREFIX: &[u8; 26] = b"\x19Polkadot Signed Message:\n";

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

    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Sr25519KeyPair::random(&mut rng);
        Ok(KeyPair::new_sr25519(kp))
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

        if (index == 0) {
            return Ok(String::new());
        }

        let index = index - 1;

        Ok(format!("//{}", index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let raw = keypair.sign_digest(digest);
        Ok(raw)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], _address: &str) -> Result<bool, Error> {
        let public = sr25519::Public::from_ss58check(_address).unwrap();

        let signature =
            sp_core::sr25519::Signature::from_raw(<[u8; 64]>::try_from(signature).unwrap());

        Ok(sr25519::Pair::verify(&signature, digest, &public))
    }

    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        todo!()
    }

    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
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
        let digest = kos_crypto::hash::blake2b256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();
        DOT::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        DOT::sign_digest(message, keypair)
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
        let address = address::Address::from_str(addr);
        Ok(address.is_ok())
    }

    pub fn decode_tx(
        genesis_hash: &str,
        spec_version: u32,
        transaction_version: u32,
        tx: &str,
    ) -> Result<Vec<u8>, Error> {
        let client = DOT::get_client(genesis_hash, spec_version, transaction_version)?;
        let tx_bytes = hex::decode(tx)?;

        let extrinsic = SubmittableExtrinsic::from_bytes(client.clone(), tx_bytes);
        Ok(Vec::from((extrinsic.encoded())))
    }

    pub fn tx_from_raw(raw: &str) -> Result<Transaction, Error> {
        let b64 = b64_engine::STANDARD;

        let bytes = b64.decode(raw).unwrap();

        let tx = DOTTransaction::from_bytes(bytes).unwrap();

        Ok(Transaction {
            chain: crate::chain::Chain::DOT,
            sender: tx.clone().address,
            hash: Hash::default(),
            data: Some(TransactionRaw::Polkadot(tx)),
        })
    }
}

impl DOT {
    pub fn get_client(
        genesis_hash: &str,
        spec_version: u32,
        transaction_version: u32,
    ) -> Result<OfflineClient<PolkadotConfig>, Error> {
        let _genesis_hash = {
            let bytes = hex::decode(genesis_hash)?;
            H256::from_slice(&bytes)
        };

        let _runtime_version = subxt::rpc::types::RuntimeVersion {
            spec_version,
            transaction_version,
            other: Default::default(),
        };

        let metadata = {
            let bytes = std::fs::read("./artifacts/polkadot_metadata_small.scale").unwrap();
            Metadata::decode(&mut &*bytes).unwrap()
        };

        Ok(OfflineClient::<PolkadotConfig>::new(
            _genesis_hash,
            _runtime_version,
            metadata,
        ))
    }
}

// Test keypair from mnemonic
#[cfg(test)]
mod tests {
    use subxt::utils::H256;

    #[test]
    fn test_keypair_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = super::DOT::get_path(&super::PathOptions {
            index: 0,
            is_legacy: None,
        })
        .unwrap();
        let kp = super::DOT::keypair_from_mnemonic(mnemonic, &path, None).unwrap();
        let address = super::DOT::get_address_from_keypair(&kp).unwrap();
        assert_eq!(address, "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo");
    }

    #[test]
    fn test_get_path() {
        let path = super::DOT::get_path(&super::PathOptions {
            index: 1,
            is_legacy: None,
        })
        .unwrap();

        assert_eq!(path, "//0");
    }

    #[test]
    fn test_validate_address() {
        let address = "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo";
        let valid = super::DOT::validate_address(address, None).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_digest() {
        let kp = super::DOT::keypair_from_bytes(&[0u8; 32]).unwrap();
        let digest = String::from("hello").into_bytes();
        let signature = super::DOT::sign_digest(&digest, &kp).unwrap();
        assert_eq!(signature.len(), 64);

        let address = super::DOT::get_address_from_keypair(&kp).unwrap();
        let valid = super::DOT::verify_digest(&digest, &signature, &address).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_get_client() {
        let client = super::DOT::get_client(
            "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            1002007,
            26,
        )
        .unwrap();

        assert_eq!(
            client.genesis_hash(),
            H256::from(&[
                145, 177, 113, 187, 21, 142, 45, 56, 72, 250, 35, 169, 241, 194, 81, 130, 251, 142,
                32, 49, 59, 44, 30, 180, 146, 25, 218, 122, 112, 206, 144, 195
            ])
        );
    }

    #[test]
    fn test_decode_tx() {
        let raw = "eyJzcGVjVmVyc2lvbiI6IjB4MDAwZjRkZjgiLCJ0cmFuc2FjdGlvblZlcnNpb24iOiIweDAwMDAwMDFhIiwiYWRkcmVzcyI6IjE0bTVvcUxFRFhNZXlkeVU4NEUyZ01NeWtLVHQ3OFFCUUZXTmpLaG5kbTFiZ0NhWCIsImFzc2V0SWQiOiJudWxsIiwiYmxvY2tIYXNoIjoiMHg2MGY4ZmFhNmI1ZGQwZmViYjE3OGU0MmViNjQ0NzE5MzU3YWU1NTViNGNiYWVmZGIzMjIwNGFmMzc5ZjRkNTg2IiwiYmxvY2tOdW1iZXIiOiIweDAxNThmYWE2IiwiZXJhIjoiMHg2NTAyIiwiZ2VuZXNpc0hhc2giOiIweDkxYjE3MWJiMTU4ZTJkMzg0OGZhMjNhOWYxYzI1MTgyZmI4ZTIwMzEzYjJjMWViNDkyMTlkYTdhNzBjZTkwYzMiLCJtZXRhZGF0YUhhc2giOiJudWxsIiwibWV0aG9kIjoiMHgwNTAzMDBhNjUzYWU3OTY2NTU2NWJhN2ZjNjgyYzM4NWIzYzAzOGMyMDkxYWI2ZDYwNTMzNTViOTk1MGExMDhhYzQ4YjA2MDAiLCJtb2RlIjowLCJub25jZSI6IjB4MDAwMDAwMDAiLCJzaWduZWRFeHRlbnNpb25zIjpbIkNoZWNrTm9uWmVyb1NlbmRlciIsIkNoZWNrU3BlY1ZlcnNpb24iLCJDaGVja1R4VmVyc2lvbiIsIkNoZWNrR2VuZXNpcyIsIkNoZWNrTW9ydGFsaXR5IiwiQ2hlY2tOb25jZSIsIkNoZWNrV2VpZ2h0IiwiQ2hhcmdlVHJhbnNhY3Rpb25QYXltZW50IiwiUHJldmFsaWRhdGVBdHRlc3RzIiwiQ2hlY2tNZXRhZGF0YUhhc2giXSwidGlwIjoiMHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInZlcnNpb24iOjQsIndpdGhTaWduZWRUcmFuc2FjdGlvbiI6dHJ1ZX0=";

        let tx = super::DOT::tx_from_raw(raw).unwrap();

        assert_eq!(
            tx.sender,
            "14m5oqLEDXMeydyU84E2gMMykKTt78QBQFWNjKhndm1bgCaX"
        );
    }
}
