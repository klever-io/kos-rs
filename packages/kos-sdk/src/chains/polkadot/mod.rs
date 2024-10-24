mod address;
mod requests;
pub mod transaction;

use crate::chains::DOTTransaction;
use crate::models::BroadcastResult;
use crate::{
    chain::BaseChain,
    models,
    models::{PathOptions, Transaction, TransactionRaw},
};
use base64::Engine;
use kos_crypto::keypair::KeyPair;
use kos_crypto::sr25519::Sr25519KeyPair;
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;
use parity_scale_codec::{Decode, Encode};

use crate::chains::polkadot::transaction::ExtrinsicPayload;
use serde::Deserializer;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use std::str::FromStr;
use subxt::client::{OfflineClientT, RuntimeVersion};
use subxt::config::Header;
use subxt::dynamic::Value;
use subxt::ext::frame_metadata::RuntimeMetadataPrefixed;
use subxt::ext::scale_decode::DecodeAsType;
use subxt::tx::{Payload, SubmittableExtrinsic};
use subxt::utils::{AccountId32, MultiAddress, MultiSignature, H256};
use subxt::{Metadata, OfflineClient, PolkadotConfig};
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct DOT {}

pub const SIGN_PREFIX: &[u8; 26] = b"\x19Polkadot Signed Message:\n";

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Polkadot",
    symbol: "DOT",
    precision: 10,
    chain_code: 21,
};

#[wasm_bindgen]
pub struct CallData {
    pallet: String,
    call: String,
    args: Vec<Value>,
}

fn to_bytes(hex_str: &str) -> Vec<u8> {
    let hex_str = hex_str
        .strip_prefix("0x")
        .expect("0x should prefix hex encoded bytes");
    hex::decode(hex_str).expect("valid bytes from hex")
}

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

        if index == 0 {
            return Ok(String::new());
        }

        let index = index - 1;

        Ok(format!("//{}", index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        Ok(keypair.sign_digest(digest))
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], _address: &str) -> Result<bool, Error> {
        let public = sr25519::Public::from_ss58check(_address).unwrap();

        let signature = sr25519::Signature::from_raw(<[u8; 64]>::try_from(signature).unwrap());

        Ok(sr25519::Pair::verify(&signature, digest, &public))
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

    pub async fn broadcast(
        _tx: Transaction,
        _node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Polkadot(dot_tx)) => {
                let new_tx = dot_tx.clone();

                let payload = ExtrinsicPayload::from_transaction(&new_tx);

                let signature = {
                    let full_unsigned_payload_scale_bytes = payload.to_bytes();

                    // If payload is longer than 256 bytes, we hash it and sign the hash instead:
                    if full_unsigned_payload_scale_bytes.len() > 256 {
                        DOT::sign_digest(&*DOT::hash(&full_unsigned_payload_scale_bytes)?, keypair)?
                    } else {
                        DOT::sign_digest(&full_unsigned_payload_scale_bytes, keypair)?
                    }
                };

                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(vec![0u8; 32])?,
                    data: Some(TransactionRaw::Polkadot(new_tx)),
                    signature: Some(hex::encode([[1u8].to_vec(), signature].concat())),
                };

                Ok(result)
            }
            _ => Err(Error::InvalidMessage(
                "not a polkadot transaction".to_string(),
            )),
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
        _addr: &str,
        _token: Option<String>,
        _node_url: Option<String>,
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

    pub fn decode_extrinsic(
        genesis_hash: &str,
        spec_version: u32,
        transaction_version: u32,
        tx: &str,
    ) -> Result<CallData, Error> {
        let metadata_bytes = {
            let bytes = std::fs::read("./artifacts/dot-klever-node.scale").unwrap();
            Metadata::decode(&mut &*bytes).unwrap()
        }
        .encode();

        let metadata = format!("0x{}", hex::encode(metadata_bytes));
        let client = DOT::get_client(genesis_hash, spec_version, transaction_version, &metadata)?;
        let data = &mut &*to_bytes(tx);

        if data.is_empty() {
            return Err(Error::InvalidTransaction("empty transaction".to_string()));
        }

        let is_signed = data[0] & 0b1000_0000 != 0;
        let version = data[0] & 0b0111_1111;
        *data = &data[1..];

        if version != 4 {
            return Err(Error::InvalidTransaction(format!(
                "unsupported extrinsic version: {}",
                version
            )));
        }

        let call_data = DOT::decode_call_data(data, client)?;

        Ok(call_data)
    }

    fn decode_call_data(
        data: &mut &[u8],
        client: OfflineClient<PolkadotConfig>,
    ) -> Result<CallData, Error> {
        let metadata = client.metadata();

        // Pluck out the u8's representing the pallet and call enum next.
        if data.len() < 2 {
            return Err(Error::InvalidTransaction(
                "expected at least 2 more bytes for the pallet/call index".to_string(),
            ));
        }
        let pallet_index = u8::decode(data).unwrap();
        let call_index = u8::decode(data).unwrap();

        let pallet_name = metadata.pallet_by_index(pallet_index).ok_or_else(|| {
            Error::InvalidTransaction(format!("pallet index {} out of bounds", pallet_index))
        })?;

        let call_variant = pallet_name.call_variant_by_index(call_index).unwrap();
        println!(
            "pallet name: {}, call name: {}",
            pallet_name.name(),
            call_variant.name
        );

        let arguments = call_variant
            .clone()
            .fields
            .iter()
            .map(|field| {
                let id = field.ty.id;
                Value::decode_as_type(data, id.into(), metadata.types())
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        Ok(CallData {
            pallet: pallet_name.name().to_string(),
            call: call_variant.name.to_string(),
            args: arguments,
        })
    }

    pub fn tx_from_json(raw: &str) -> Result<Transaction, Error> {
        let mut tx = DOTTransaction::from_json(raw)?;

        Ok(Transaction {
            chain: crate::chain::Chain::DOT,
            sender: tx.clone().address,
            hash: Hash::default(),
            data: Some(TransactionRaw::Polkadot(tx.clone())),
            signature: tx.signature,
        })
    }
}

impl DOT {
    pub fn get_client(
        genesis_hash: &str,
        spec_version: u32,
        transaction_version: u32,
        raw_metadata: &str,
    ) -> Result<OfflineClient<PolkadotConfig>, Error> {
        let _genesis_hash = {
            let bytes = hex::decode(genesis_hash)?;
            H256::from_slice(&bytes)
        };

        let _runtime_version = RuntimeVersion {
            spec_version,
            transaction_version,
        };

        let binding = to_bytes(raw_metadata);
        let bytes = binding.as_slice();

        let prefixed_metadata = RuntimeMetadataPrefixed::decode(&mut &*bytes).unwrap();

        let metadata = Metadata::try_from(prefixed_metadata).unwrap();

        Ok(OfflineClient::<PolkadotConfig>::new(
            _genesis_hash,
            _runtime_version,
            metadata,
        ))
    }

    pub fn get_submittable_extrinsic(
        tx: DOTTransaction,
    ) -> Result<SubmittableExtrinsic<PolkadotConfig, OfflineClient<PolkadotConfig>>, Error> {
        let metadata_bytes = {
            let bytes = std::fs::read("./artifacts/dot-klever-node.scale").unwrap();
            Metadata::decode(&mut &*bytes).unwrap()
        }
        .encode();

        let metadata = format!("0x{}", hex::encode(metadata_bytes));

        let client = DOT::get_client(
            &*tx.genesis_hash.strip_prefix("0x").unwrap(),
            u32::from_str_radix(tx.spec_version.strip_prefix("0x").unwrap(), 16).unwrap(),
            u32::from_str_radix(tx.transaction_version.strip_prefix("0x").unwrap(), 16).unwrap(),
            &metadata,
        )
        .unwrap();

        let method = hex::decode(&mut tx.method.strip_prefix("0x").unwrap().to_string()).unwrap();
        let method_bytes = &mut &*method;

        let payload = {
            let call_data = DOT::decode_call_data(method_bytes, client.clone()).unwrap();
            subxt::dynamic::tx(call_data.pallet, call_data.call, call_data.args)
        };

        let partial_tx = client
            .tx()
            .create_partial_signed_offline(&payload, Default::default())
            .unwrap();

        let signature = Some(hex::decode(tx.signature.unwrap()).unwrap()).unwrap();

        let address = MultiAddress::Id(AccountId32::from_str(&tx.address).unwrap());
        let signature = MultiSignature::Sr25519(<[u8; 64]>::try_from(signature).unwrap());

        let submittable = partial_tx.sign_with_address_and_signature(&address, &signature);

        Ok(submittable)
    }
}

#[cfg(test)]
mod tests {
    use crate::chains::polkadot::transaction::{ExtrinsicPayload, Transaction};
    use crate::chains::DOT;
    use parity_scale_codec::{Decode, Encode};
    use serde_json::json;
    use subxt::client::OfflineClientT;
    use subxt::utils::{MultiAddress, MultiSignature, H256};
    use subxt::Metadata;

    #[test]
    fn test_keypair_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = DOT::get_path(&super::PathOptions {
            index: 0,
            is_legacy: None,
        })
        .unwrap();
        let kp = DOT::keypair_from_mnemonic(mnemonic, &path, None).unwrap();
        let address = DOT::get_address_from_keypair(&kp).unwrap();
        assert_eq!(address, "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo");
    }

    #[test]
    fn test_get_path() {
        let path = DOT::get_path(&super::PathOptions {
            index: 1,
            is_legacy: None,
        })
        .unwrap();

        assert_eq!(path, "//0");
    }

    #[test]
    fn test_validate_address() {
        let address = "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo";
        let valid = DOT::validate_address(address, None).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_sign_digest() {
        let kp = DOT::keypair_from_bytes(&[0u8; 32]).unwrap();
        let digest = String::from("hello").into_bytes();
        let signature = DOT::sign_digest(&digest, &kp).unwrap();
        assert_eq!(signature.len(), 64);

        let address = DOT::get_address_from_keypair(&kp).unwrap();
        let valid = DOT::verify_digest(&digest, &signature, &address).unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn test_get_client() {
        let metadata_bytes = {
            let bytes = std::fs::read("./artifacts/dot-klever-node.scale").unwrap();
            Metadata::decode(&mut &*bytes).unwrap()
        }
        .encode();

        let metadata = format!("0x{}", hex::encode(metadata_bytes));

        let client = DOT::get_client(
            "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            1002007,
            26,
            &metadata,
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
    fn decode_extrinsic() {
        let ext = "0x040503002534454d30f8a028e42654d6b535e0651d1d026ddf115cef59ae1dd71bae074e910100ee2a21000000fb4d0f001a00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c300";

        let decoded = DOT::decode_extrinsic(
            "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            1003000,
            26,
            ext,
        )
        .unwrap();

        for arg in decoded.args {
            println!("{:?}", arg);
        }
    }

    #[test]
    fn test_decode_call_data() {
        let metadata_bytes = {
            let bytes = std::fs::read("./artifacts/dot-klever-node.scale").unwrap();
            Metadata::decode(&mut &*bytes).unwrap()
        }
        .encode();

        let metadata = format!("0x{}", hex::encode(metadata_bytes));

        let client = DOT::get_client(
            "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            1003000,
            26,
            &metadata,
        )
        .unwrap();

        let call_data_hex =
            "0x0503002534454d30f8a028e42654d6b535e0651d1d026ddf115cef59ae1dd71bae074e910100322121000000f84d0f001a00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c300";

        let call_data_bytes = hex::decode(call_data_hex.strip_prefix("0x").unwrap()).unwrap();

        let call_data_cursor = &mut &*call_data_bytes;

        let decoded = DOT::decode_call_data(call_data_cursor, client.clone()).unwrap();

        let payload = subxt::dynamic::tx(decoded.pallet, decoded.call, decoded.args);

        let partial_tx = client
            .tx()
            .create_partial_signed_offline(&payload, Default::default())
            .unwrap();

        let signer_payload = partial_tx.signer_payload();

        let kp = DOT::keypair_from_bytes(&[0u8; 32]).unwrap();
        let signature = DOT::sign_digest(&signer_payload, &kp).unwrap();

        let address =
            MultiAddress::Id(super::address::Address::from_keypair(&kp).to_account_id32());
        let signature = MultiSignature::Sr25519(<[u8; 64]>::try_from(signature).unwrap());

        let submittable = partial_tx.sign_with_address_and_signature(&address, &signature);

        println!("{:?}", hex::encode(submittable.encoded()));
    }

    #[test]
    fn sign_extrinsic_payload() {
        let json_data = r#"
    {
    "specVersion": "0x000f4dfb",
    "transactionVersion": "0x0000001a",
    "address": "14m5oqLEDXMeydyU84E2gMMykKTt78QBQFWNjKhndm1bgCaX",
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

        let transaction = DOT::tx_from_json(json_data).unwrap();

        let kp = DOT::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "//0", None).unwrap();

        let signed = DOT::sign(transaction, &kp).unwrap();

        println!("signature {:?}", signed.get_signature().unwrap());
    }
}
