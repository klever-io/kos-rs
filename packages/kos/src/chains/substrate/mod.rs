mod models;

use crate::chains::substrate::models::ExtrinsicPayload;
use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainOptions, Transaction, TxInfo};
use crate::crypto::hash::{blake2b_64_digest, blake2b_digest};
use crate::crypto::sr25519::Sr25519Trait;
use crate::crypto::{b58, bip32, sr25519};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use models::{Call, CallArgs};
use parity_scale_codec::Decode;

const LOWER_MASK: u16 = 0x3FFF;
const TYPE1_ACCOUNT_ID: u16 = 63;
const IDENTIFIER_LOWER_MASK: u16 = 0x00FC;
const IDENTIFIER_UPPER_MASK: u16 = 0x0003;
const IDENTIFIER_LOWER_PREFIX: u8 = 0x40;
const SUBSTRATE_NETWORK_PREFIX: &str = "SS58PRE";

pub struct Substrate {
    id: u32,
    network_id: u16,
    name: String,
    symbol: String,
}

impl Substrate {
    pub fn new(id: u32, network_id: u16, name: &str, symbol: &str) -> Self {
        Self {
            id,
            network_id,
            name: name.to_string(),
            symbol: symbol.to_string(),
        }
    }
}

impl Chain for Substrate {
    fn get_id(&self) -> u32 {
        self.id
    }

    fn get_name(&self) -> &str {
        self.name.as_str()
    }

    fn get_symbol(&self) -> &str {
        self.symbol.as_str()
    }

    fn get_decimals(&self) -> u32 {
        12
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed_substrate(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive_sr25519(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        if index == 0 {
            return String::new();
        }

        format!("//{}", index - 1)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = sr25519::Sr25519::public_from_private(&pvk)?;
        pvk.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let identifier = self.network_id & LOWER_MASK;
        let mut prefix = Vec::new();
        if identifier < TYPE1_ACCOUNT_ID {
            prefix.push(identifier as u8);
        } else {
            let lower_byte = ((identifier & IDENTIFIER_LOWER_MASK) >> 2) as u8;
            let upper_byte =
                ((identifier >> 8) | ((identifier & IDENTIFIER_UPPER_MASK) << 6)) as u8;
            prefix.push(lower_byte | IDENTIFIER_LOWER_PREFIX);
            prefix.push(upper_byte);
        }

        let data_to_hash = [
            SUBSTRATE_NETWORK_PREFIX.as_bytes(),
            &prefix[..],
            &public_key[..],
        ]
        .concat();
        let digest = blake2b_64_digest(&data_to_hash);

        let to_base_58 = [&prefix[..], &public_key[..], &digest[..2]].concat();
        let encoded = b58::b58enc(&to_base_58);
        let addr = String::from_utf8(encoded).unwrap();
        Ok(addr)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let options = tx.options.clone().ok_or(ChainError::MissingOptions)?;

        let extrinsic = match options {
            ChainOptions::SUBSTRATE {
                call,
                era,
                nonce,
                tip,
                block_hash,
                genesis_hash,
                spec_version,
                transaction_version,
                app_id,
            } => {
                let genesis_hash: [u8; 32] = genesis_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::InvalidOptions)?;

                let block_hash: [u8; 32] = block_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::InvalidOptions)?;

                // Other chains may have different requirements for mode and metadata_hash
                let (mode, metadata_hash) = match self.symbol.as_str() {
                    "REEF" => (None, None),
                    _ => (Some(0u8), Some(0u8)),
                };

                ExtrinsicPayload {
                    call,
                    era,
                    nonce,
                    tip,
                    mode,
                    spec_version,
                    transaction_version,
                    genesis_hash,
                    block_hash,
                    metadata_hash,
                    app_id,
                }
            }
            _ => {
                return Err(ChainError::InvalidOptions);
            }
        };

        let signature = {
            let full_unsigned_payload_scale_bytes = extrinsic.to_bytes();

            // If payload is longer than 256 bytes, we hash it and sign the hash instead:
            if full_unsigned_payload_scale_bytes.len() > 256 {
                self.sign_raw(
                    private_key.clone(),
                    blake2b_digest(&full_unsigned_payload_scale_bytes).to_vec(),
                )?
            } else {
                self.sign_raw(private_key.clone(), full_unsigned_payload_scale_bytes)?
            }
        };

        let pbk_vec = self.get_pbk(private_key)?;
        let public_key: [u8; 32] = pbk_vec
            .try_into()
            .map_err(|_| ChainError::InvalidPublicKey)?;

        tx.raw_data = extrinsic.encode_with_signature(&public_key, &signature);

        tx.signature = [[1u8].to_vec(), signature].concat();
        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        self.sign_raw(private_key, message)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut private_key_bytes = private_key_from_vec(&private_key)?;
        let sig = sr25519::Sr25519::sign(&payload, &private_key_bytes)?;
        private_key_bytes.fill(0);
        Ok(sig)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        let info = Call::decode(&mut &_raw_tx[..]).map_err(|_| ChainError::InvalidPrivateKey)?;
        let args = info.args.to_vec();
        let tx_info =
            CallArgs::decode(&mut &args[..]).map_err(|_| ChainError::InvalidPrivateKey)?;
        let address_to = self.get_address(tx_info.addr_to.to_vec())?;
        let new_tx_info = TxInfo {
            receiver: address_to,
            sender: "".to_string(),
            tx_type: super::TxType::Unknown,
            value: tx_info.amount.to_f64(self.get_decimals()),
        };
        Ok(new_tx_info)
    }
}

#[cfg(test)]
mod test {
    use crate::chains::{Chain, ChainOptions, Transaction};
    use crate::crypto::base64::simple_base64_decode;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TxBrowser {
        #[serde(rename = "specVersion")]
        pub spec_version: String,
        #[serde(rename = "transactionVersion")]
        pub transaction_version: String,
        #[serde(rename = "address")]
        pub _address: String,
        #[serde(rename = "assetId")]
        pub _asset_id: Option<String>,
        #[serde(rename = "blockHash")]
        pub block_hash: String,
        #[serde(rename = "blockNumber")]
        pub _block_number: String,
        pub era: String,
        #[serde(rename = "genesisHash")]
        pub genesis_hash: String,
        #[serde(rename = "metadataHash")]
        pub _metadata_hash: Option<String>,
        pub method: String,
        #[serde(rename = "mode")]
        pub _mode: i64,
        pub nonce: String,
        #[serde(rename = "signedExtensions")]
        pub _signed_extensions: Vec<String>,
        pub tip: String,
        #[serde(rename = "version")]
        pub _version: i64,
        #[serde(rename = "withSignedTransaction")]
        pub _with_signed_transaction: bool,
    }

    fn options_from_browser_json(tx: String) -> ChainOptions {
        let tx_browser: TxBrowser = serde_json::from_str(&tx).unwrap();
        let call = hex::decode(tx_browser.method.trim_start_matches("0x")).unwrap();
        let era = hex::decode(tx_browser.era.trim_start_matches("0x")).unwrap();
        let nonce = u32::from_str_radix(tx_browser.nonce.trim_start_matches("0x"), 16).unwrap();
        let tip = u8::from_str_radix(tx_browser.tip.trim_start_matches("0x"), 16).unwrap();
        let block_hash = hex::decode(tx_browser.block_hash.trim_start_matches("0x")).unwrap();
        let genesis_hash = hex::decode(tx_browser.genesis_hash.trim_start_matches("0x")).unwrap();
        let spec_version =
            u32::from_str_radix(tx_browser.spec_version.trim_start_matches("0x"), 16).unwrap();
        let transaction_version =
            u32::from_str_radix(tx_browser.transaction_version.trim_start_matches("0x"), 16)
                .unwrap();
        let app_id = None;

        ChainOptions::SUBSTRATE {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        }
    }

    #[test]
    fn test_get_addr_1() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo");
    }
    #[test]
    fn test_get_addr_2() {
        let dot = super::Substrate::new(62, 42, "AVAIL", "Avail");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "5DvaFrBesD6jTWd3GEefcM72BSXaFRHqQuZtwBSZii1VMnuP");
    }
    #[test]
    fn test_get_addr_3() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "12rsQBSiizNCu3dZDshfkVwB34XDwiqyVQJP6URvGo31YGdp");
    }

    #[test]
    fn test_sign_raw() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = String::from("");

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let payload = [0; 32].to_vec();
        let sig = dot.sign_raw(pvk, payload).unwrap();

        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_tx_1() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BQMADCRBuM7b/Hou3AlouaU1gZlp0+ngmYaAurtYJyh/wHAE1QFsAAD8TQ8AGgAAAJGxcbsVji04SPojqfHCUYL7jiAxOywetJIZ2npwzpDDR+4cSO05ZyHnTfHIHpWyqrPhN2Poot7H7VqLlK9MgI0A").unwrap();

        let options = ChainOptions::SUBSTRATE {
            call: hex::decode(
                "0503000c2441b8cedbfc7a2edc0968b9a535819969d3e9e0998680babb5827287fc07004",
            )
            .unwrap(),
            era: hex::decode("d501").unwrap(),
            nonce: 27,
            tip: 0,
            block_hash: hex::decode(
                "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            )
            .unwrap(),
            genesis_hash: hex::decode(
                "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            )
            .unwrap(),
            spec_version: 1003004,
            transaction_version: 26,
            app_id: None,
        };

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: Some(options),
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();

        assert_eq!(signed_tx.signature.len(), 65);
        assert_eq!(signed_tx.raw_data.len(), 142);
    }

    #[test]
    fn sign_tx_2() {
        let dot = super::Substrate::new(27, 2, "Kusama", "KSM");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BgMATg7dBMR7Gtw7IdzYZxpdkKHC63X7YNKTqQhvJibbzVkEJQEcAAAoAAAAAQAAALkXRrReA0bML4FaUgucbLTVwJAq+EjbCoD4WTLS6CdqrE2opg7XFpDCJ63rn+zxU3cs7DhW6Sm5cCF02Gg1wDY=").unwrap();

        let options = ChainOptions::SUBSTRATE {
            call: hex::decode(
                "0403004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904",
            )
            .unwrap(),
            era: hex::decode("4502").unwrap(),
            nonce: 87,
            tip: 0,
            block_hash: hex::decode(
                "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
            )
            .unwrap(),
            genesis_hash: hex::decode(
                "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
            )
            .unwrap(),
            spec_version: 1003003,
            transaction_version: 26,
            app_id: None,
        };

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: Some(options),
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();

        assert_eq!(signed_tx.signature.len(), 65);
        assert_eq!(signed_tx.raw_data.len(), 143);
    }

    #[test]
    fn sign_tx_3() {
        let dot = super::Substrate::new(62, 42, "Avail", "AVAIL");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BgMATg7dBMR7Gtw7IdzYZxpdkKHC63X7YNKTqQhvJibbzVkEtQEgAAAoAAAAAQAAALkXRrReA0bML4FaUgucbLTVwJAq+EjbCoD4WTLS6CdqDhX+2GUB2kR8rjtzYfwUoIfzCa63UQhdcamIqku0qBE=").unwrap();

        let nonce = u32::from_str_radix("0x00000008".trim_start_matches("0x"), 16).unwrap();
        let spec_version = u32::from_str_radix("0x00000028".trim_start_matches("0x"), 16).unwrap();
        let transaction_version =
            u32::from_str_radix("0x00000001".trim_start_matches("0x"), 16).unwrap();

        let options = ChainOptions::SUBSTRATE {
            call: hex::decode(
                "0603004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904",
            )
            .unwrap(),
            era: hex::decode("b501").unwrap(),
            nonce,
            tip: 0,
            block_hash: hex::decode(
                "0e15fed86501da447cae3b7361fc14a087f309aeb751085d71a988aa4bb4a811",
            )
            .unwrap(),
            genesis_hash: hex::decode(
                "b91746b45e0346cc2f815a520b9c6cb4d5c0902af848db0a80f85932d2e8276a",
            )
            .unwrap(),
            spec_version,
            transaction_version,
            app_id: Some(0),
        };

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: Some(options),
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();

        assert_eq!(signed_tx.signature.len(), 65);
        assert_eq!(signed_tx.raw_data.len(), 142);
    }

    #[test]
    fn sign_tx_4() {
        let dot = super::Substrate::new(29, 42, "REEF", "Reef");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BgMAIBAGX9aAF/hRd/ms+YCatuNZ7HYxyfly/j75aXrwkxMEFQNgAAoAAAACAAAAeDR4HTjkeY1UjjTslH0Z3uop3xSKe/MkhLeyTaz41LdWfCQku+9zEoyAsxnOxPxhQOEisj7yIJbyvkGmUcrXaw==").unwrap();

        let nonce = 24;
        let spec_version = 10;
        let transaction_version = 2;

        let options = ChainOptions::SUBSTRATE {
            call: hex::decode(
                "0603002010065fd68017f85177f9acf9809ab6e359ec7631c9f972fe3ef9697af0931304",
            )
            .unwrap(),
            era: hex::decode("1503").unwrap(),
            nonce,
            tip: 0,
            block_hash: hex::decode(
                "567c2424bbef73128c80b319cec4fc6140e122b23ef22096f2be41a651cad76b",
            )
            .unwrap(),
            genesis_hash: hex::decode(
                "7834781d38e4798d548e34ec947d19deea29df148a7bf32484b7b24dacf8d4b7",
            )
            .unwrap(),
            spec_version,
            transaction_version,
            app_id: None,
        };

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: Some(options),
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();

        assert_eq!(signed_tx.signature.len(), 65);
        assert_eq!(signed_tx.raw_data.len(), 142);
    }

    #[test]
    fn sign_tx_browser() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BQMADCRBuM7b/Hou3AlouaU1gZlp0+ngmYaAurtYJyh/wHAE1QFsAAD8TQ8AGgAAAJGxcbsVji04SPojqfHCUYL7jiAxOywetJIZ2npwzpDDR+4cSO05ZyHnTfHIHpWyqrPhN2Poot7H7VqLlK9MgI0A").unwrap();

        let options = options_from_browser_json(
            r#"{
                "specVersion": "0x000f4dfc",
                "transactionVersion": "0x0000001a",
                "address": "12mM9imBfhL4DfK2Sv9SPi79kKT296YJ6LTT7b7pZuRufXmx",
                "assetId": null,
                "blockHash": "0x74e061f402b8709b793aede7509ac32ca2bf60ab772035e8de2c3b597a99c3cd",
                "blockNumber": "0x017870fe",
                "era": "0xe503",
                "genesisHash": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                "metadataHash": null,
                "method": "0x0503004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5900",
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
            }"#
                .to_string(),
        );

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: Some(options),
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();

        assert_eq!(signed_tx.signature.len(), 65);
        assert_eq!(signed_tx.raw_data.len(), 142);
    }

    #[test]
    fn test_get_tx_info() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");
        let raw_data = "05030092fb4dc4e0790663aa4be18e6c49d62e8db091a6e1c4d0727c14906cf79f0f7a280000002b460f001900000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3".to_string();

        let raw_data_hex = hex::decode(raw_data).unwrap();
        let tx_info = dot.get_tx_info(raw_data_hex);
        assert!(tx_info.is_ok());
    }
}
