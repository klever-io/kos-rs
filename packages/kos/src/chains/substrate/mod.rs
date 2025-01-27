mod models;

use crate::chains::substrate::models::ExtrinsicPayload;
use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::hash::{blake2b_64_digest, blake2b_digest};
use crate::crypto::sr25519::Sr25519Trait;
use crate::crypto::{b58, bip32, sr25519};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use models::{Call, CallArgs};
use parity_scale_codec::{Decode, Encode};

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
        let extrinsic = ExtrinsicPayload::from_raw(tx.raw_data.clone())?;

        let signature = {
            let full_unsigned_payload_scale_bytes = extrinsic.to_bytes();

            // If payload is longer than 256 bytes, we hash it and sign the hash instead:
            if full_unsigned_payload_scale_bytes.len() > 256 {
                self.sign_raw(
                    private_key,
                    blake2b_digest(&full_unsigned_payload_scale_bytes)?,
                )?
            } else {
                self.sign_raw(private_key, full_unsigned_payload_scale_bytes)?
            }
        };

        // tx.raw_data = extrinsic.encode_signed(tx.raw_data, sig.clone());

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
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("BQMADCRBuM7b/Hou3AlouaU1gZlp0+ngmYaAurtYJyh/wHCRAXUCSAAA/E0PABoAAACRsXG7FY4tOEj6I6nxwlGC+44gMTssHrSSGdp6cM6Qw9QXMtYkIUOthrBb+DGJV708aGKwcFqtBLEzg3sSYncgAA==").unwrap();

        let tx = Transaction {
            raw_data,
            signature: Vec::new(),
            tx_hash: Vec::new(),
            options: None,
        };

        let signed_tx = dot.sign_tx(pvk, tx).unwrap();
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
