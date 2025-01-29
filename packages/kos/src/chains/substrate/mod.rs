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
            return "".to_string();
        }
        format!("//{}", index)
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
            } => {
                let genesis_hash: [u8; 32] = genesis_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::InvalidOptions)?;

                let block_hash: [u8; 32] = block_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::InvalidOptions)?;

                ExtrinsicPayload {
                    call,
                    era,
                    nonce,
                    tip,
                    mode: 0,
                    spec_version,
                    transaction_version,
                    genesis_hash,
                    block_hash,
                    metadata_hash: 0,
                }
            }
            _ => {
                return Err(ChainError::InvalidOptions);
            }
        };

        let signature = {
            let full_unsigned_payload_scale_bytes = tx.raw_data.clone();

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

fn new_substrate_transaction_options(
    call: String,
    era: String,
    nonce: String,
    tip: String,
    block_hash: String,
    genesis_hash: String,
    spec_version: String,
    transaction_version: String,
) -> ChainOptions {
    let call = hex::decode(call).unwrap();
    let era = hex::decode(era).unwrap();
    let nonce: u32 = nonce.parse().unwrap();
    let tip: u8 = tip.parse().unwrap();
    let block_hash = hex::decode(block_hash).unwrap();
    let genesis_hash = hex::decode(genesis_hash).unwrap();
    let spec_version: u32 = spec_version.parse().unwrap();
    let transaction_version: u32 = transaction_version.parse().unwrap();

    ChainOptions::SUBSTRATE {
        call,
        era,
        nonce,
        tip,
        block_hash,
        genesis_hash,
        spec_version,
        transaction_version,
    }
}

#[cfg(test)]
mod test {
    use crate::chains::substrate::new_substrate_transaction_options;
    use crate::chains::{Chain, Transaction};
    use crate::crypto::base64::simple_base64_decode;
    use alloc::string::{String, ToString};

    #[test]
    fn test_get_addr() {
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
    fn test_get_addr1() {
        let dot = super::Substrate::new(62, 42, "AVAIL", "Avail");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "5DJ8y4CAHnmjt4rdoZpR1wgXnQDnKDksskx7JTphZhMxthiG");
    }

    #[test]
    fn test_sign_raw() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = String::from("");

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let payload = [0; 32].to_vec();
        let _tx = dot.sign_raw(pvk, payload).unwrap();
    }

    #[test]
    fn sign_tx() {
        let dot = super::Substrate::new(27, 2, "Kusama", "KSM");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BgMATg7dBMR7Gtw7IdzYZxpdkKHC63X7YNKTqQhvJibbzVkEJQEcAAAoAAAAAQAAALkXRrReA0bML4FaUgucbLTVwJAq+EjbCoD4WTLS6CdqrE2opg7XFpDCJ63rn+zxU3cs7DhW6Sm5cCF02Gg1wDY=").unwrap();

        let options = new_substrate_transaction_options(
            "0403004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904".to_string(),
            "4502".to_string(),
            "87".to_string(),
            "0".to_string(),
            "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe".to_string(),
            "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe".to_string(),
            "1003003".to_string(),
            "26".to_string(),
        );

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
    fn test_get_tx_info() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");
        let raw_data = "05030092fb4dc4e0790663aa4be18e6c49d62e8db091a6e1c4d0727c14906cf79f0f7a280000002b460f001900000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3".to_string();

        let raw_data_hex = hex::decode(raw_data).unwrap();
        let tx_info = dot.get_tx_info(raw_data_hex);
        assert!(tx_info.is_ok());
    }
}
