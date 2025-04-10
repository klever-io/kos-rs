use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo, TxType};
use crate::crypto::b58::b58enc;
use crate::crypto::bignum::U256;
use crate::crypto::hash::{keccak256_digest, sha256_digest};
use crate::crypto::secp256k1::Secp256k1Trait;
use crate::crypto::{bip32, secp256k1};
use crate::protos::generated::trx::protocol;
use crate::protos::generated::trx::protocol::transaction::contract::ContractType;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use prost::Message;

const TRX_ADDR_PREFIX: u8 = 0x41;
const TRX_ADD_RAW_LEN: usize = 21;
const TRX_ADD_SIZE: usize = 25;

pub const BIP44_PATH: u32 = 195;

const TRON_MESSAGE_PREFIX: &str = "\x19TRON Signed Message:\n";
pub struct TRX {}

impl TRX {
    pub fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let mut msg = Vec::new();
        msg.extend_from_slice(TRON_MESSAGE_PREFIX.as_bytes());
        msg.extend_from_slice(message.len().to_string().as_bytes());
        msg.extend_from_slice(&message);

        keccak256_digest(&msg[..])
    }

    pub fn expand_address_with_checksum(address: &[u8; 21]) -> String {
        let mut address_with_checksum: [u8; TRX_ADD_SIZE] = [0; TRX_ADD_SIZE];
        address_with_checksum[..TRX_ADD_RAW_LEN].copy_from_slice(&address[..]);
        let hash = sha256_digest(&address_with_checksum[..TRX_ADD_RAW_LEN]);
        let hash = sha256_digest(&hash[..]);
        address_with_checksum[21..].copy_from_slice(&hash[0..4]);
        let bytes_addr = b58enc(&address_with_checksum[..]);
        String::from_utf8(bytes_addr).unwrap()
    }

    #[allow(clippy::single_match)]
    pub fn decode_transaction(raw_tx: Vec<u8>) -> Result<protocol::Transaction, ChainError> {
        let tx = protocol::Transaction::decode(raw_tx.as_slice());
        match tx {
            Ok(t) => return Ok(t),
            Err(_) => {}
        }

        let raw_tx = protocol::transaction::Raw::decode(raw_tx.as_slice())?;
        let tx = protocol::Transaction {
            raw_data: Some(raw_tx),
            signature: vec![],
            ret: vec![],
        };

        Ok(tx)
    }
}

impl Chain for TRX {
    fn get_id(&self) -> u32 {
        1
    }

    fn get_name(&self) -> &str {
        "TRON"
    }

    fn get_symbol(&self) -> &str {
        "TRX"
    }

    fn get_decimals(&self) -> u32 {
        6
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(Vec::from(pvk))
    }

    fn get_path(&self, index: u32, is_legacy: bool) -> String {
        if is_legacy {
            format!("m/44'/{}'/{}'", BIP44_PATH, index)
        } else {
            format!("m/44'/{}'/0'/0/{}", BIP44_PATH, index)
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = secp256k1::Secp256K1::private_to_public_uncompressed(&pvk)?;
        pvk.fill(0);
        Ok(Vec::from(pbk))
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let hash = keccak256_digest(&public_key[1..]);

        let mut address: [u8; TRX_ADD_RAW_LEN] = [0; TRX_ADD_RAW_LEN];
        address[0] = TRX_ADDR_PREFIX;
        address[1..TRX_ADD_RAW_LEN].copy_from_slice(&hash[12..]);
        Ok(TRX::expand_address_with_checksum(&address))
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let raw_tx = tx.raw_data;

        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pvk_bytes: [u8; 32] = [0; 32];
        pvk_bytes.copy_from_slice(&private_key[..32]);
        let mut tron_tx = TRX::decode_transaction(raw_tx)?;

        let raw_data_clone = tron_tx
            .raw_data
            .clone()
            .ok_or(ChainError::ProtoDecodeError)?;
        let mut tx_raw = Vec::new();
        raw_data_clone.encode(&mut tx_raw)?;

        let tx_id = sha256_digest(&tx_raw[..]);
        let sig = secp256k1::Secp256K1::sign(&tx_id, &pvk_bytes)?;

        tron_tx.signature.push(sig.to_vec());

        let mut tx_data = Vec::new();
        tron_tx.encode(&mut tx_data)?;

        tx.raw_data = tx_data;
        tx.tx_hash = tx_id.to_vec();
        tx.signature = sig.as_slice().to_vec();
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pvk_bytes: [u8; 32] = [0; 32];
        pvk_bytes.copy_from_slice(&private_key[..32]);

        let parsed_message = TRX::prepare_message(message);
        let sig = self.sign_raw(private_key, parsed_message.to_vec())?;
        Ok(sig.as_slice().to_vec())
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = secp256k1::Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        let tx = TRX::decode_transaction(raw_tx)?;
        let raw = tx.raw_data.ok_or(ChainError::ProtoDecodeError)?;
        if raw.contract.is_empty() {
            return Err(ChainError::ProtoDecodeError);
        }

        let contract = raw.contract[0].clone();

        let contract_type =
            ContractType::try_from(contract.r#type).map_err(|_| ChainError::ProtoDecodeError)?;
        let parameter = contract.parameter.ok_or(ChainError::ProtoDecodeError)?;

        match contract_type {
            ContractType::TransferContract => {
                let transfer_contract =
                    protocol::TransferContract::decode(parameter.value.as_slice())?;
                let mut owner_u8_addr: [u8; 21] = [0; 21];
                let mut owner_address = String::from("");

                if transfer_contract.owner_address.len() >= TRX_ADD_RAW_LEN {
                    owner_u8_addr.copy_from_slice(&transfer_contract.owner_address[..]);
                    owner_address = TRX::expand_address_with_checksum(&owner_u8_addr);
                }

                let mut to_u8_addr: [u8; 21] = [0; 21];
                let mut to_address = String::from("");

                if transfer_contract.to_address.len() >= TRX_ADD_RAW_LEN {
                    to_u8_addr.copy_from_slice(&transfer_contract.to_address[..]);
                    to_address = TRX::expand_address_with_checksum(&to_u8_addr);
                }

                let value = U256::from_i64(transfer_contract.amount).to_f64(self.get_decimals());
                return Ok(TxInfo {
                    sender: owner_address,
                    receiver: to_address,
                    value,
                    tx_type: TxType::Transfer,
                });
            }

            ContractType::TransferAssetContract => {
                let transfer_contract: protocol::TransferAssetContract =
                    protocol::TransferAssetContract::decode(parameter.value.as_slice())?;
                let mut owner_u8_addr: [u8; 21] = [0; 21];
                let mut owner_address = String::from("");

                if transfer_contract.owner_address.len() >= TRX_ADD_RAW_LEN {
                    owner_u8_addr.copy_from_slice(&transfer_contract.owner_address[..]);
                    owner_address = TRX::expand_address_with_checksum(&owner_u8_addr);
                }

                let mut to_u8_addr: [u8; 21] = [0; 21];
                let mut to_address = String::from("");

                if transfer_contract.to_address.len() >= TRX_ADD_RAW_LEN {
                    to_u8_addr.copy_from_slice(&transfer_contract.to_address[..]);
                    to_address = TRX::expand_address_with_checksum(&to_u8_addr);
                }

                let value = U256::from_i64(transfer_contract.amount).to_f64(self.get_decimals());
                return Ok(TxInfo {
                    sender: owner_address,
                    receiver: to_address,
                    value,
                    tx_type: TxType::Transfer,
                });
            }

            ContractType::TriggerSmartContract => {
                let trigger_contract =
                    protocol::TriggerSmartContract::decode(parameter.value.as_slice())?;
                let mut owner_u8_addr: [u8; 21] = [0; 21];
                let mut owner_address = String::from("");

                if trigger_contract.owner_address.len() >= TRX_ADD_RAW_LEN {
                    owner_u8_addr.copy_from_slice(&trigger_contract.owner_address[..]);
                    owner_address = TRX::expand_address_with_checksum(&owner_u8_addr);
                }

                let mut to_u8_addr: [u8; 21] = [0; 21];
                let mut to_address = String::from("");

                if trigger_contract.contract_address.len() >= TRX_ADD_RAW_LEN {
                    to_u8_addr.copy_from_slice(&trigger_contract.contract_address[..]);
                    to_address = TRX::expand_address_with_checksum(&to_u8_addr);
                }

                return Ok(TxInfo {
                    sender: owner_address,
                    receiver: to_address,
                    value: 0.0,
                    tx_type: TxType::TriggerContract,
                });
            }
            _ => {}
        };

        Ok(TxInfo {
            sender: "".to_string(),
            receiver: "".to_string(),
            value: 0.0,
            tx_type: TxType::Unknown,
        })
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::TRX
    }
}

#[cfg(test)]
mod test {
    use crate::chains::{Chain, Transaction};
    use alloc::string::{String, ToString};
    use alloc::vec;

    #[test]
    fn test_trx_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = crate::chains::trx::TRX {}
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = crate::chains::trx::TRX {}.get_path(0, false);
        let pvk = crate::chains::trx::TRX {}.derive(seed, path).unwrap();
        assert_eq!(pvk.len(), 32);
        let pbk = crate::chains::trx::TRX {}.get_pbk(pvk).unwrap();
        assert_eq!(pbk.len(), 65);
        let addr = crate::chains::trx::TRX {}.get_address(pbk).unwrap();
        assert_eq!(addr, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    }

    #[test]
    fn test_sign_tx() {
        let hex_tx = hex::decode(
            "0a02487c22080608af18\
        f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65\
        617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e74\
        7261637412300a1541e825d52582eec346c839b4875376117904a76cbc121\
        54120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031",
        )
        .unwrap();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = String::from("m/44'/195'/0'/0/0");

        let seed = crate::chains::trx::TRX {}
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let pvk = crate::chains::trx::TRX {}.derive(seed, path).unwrap();
        assert_eq!(pvk.len(), 32);

        let tx = Transaction {
            raw_data: hex_tx,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };
        let _tx = crate::chains::trx::TRX {}.sign_tx(pvk, tx).unwrap();
    }

    #[test]
    fn test_decode_tx() {
        let hex_tx = hex::decode("0a022986220894d3a7d6c869ebc840c0e1b2b5e1315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a70ae9cafb5e131").unwrap();

        let info = crate::chains::trx::TRX {}.get_tx_info(hex_tx).unwrap();
        let res = tiny_json_rs::encode(info);
        assert_eq!(
            res,
            r#"{"receiver":"TCwwZeH6so1X4R5kcdbKqa4GWuzF53xPqG","sender":"TX8h6Df74VpJsXF6sTDz1QJsq3Ec8dABc3","tx_type":"Transfer","value":0.00001}"#
        );
    }

    #[test]
    fn test_sign_message() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let chain = super::TRX {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = chain.sign_message(pvk, message_bytes, false).unwrap();

        assert_eq!(
            hex::encode(signature),
            "cf7b64342bc41955671164c8d5fe7ee992e9497ff4bedcad02f7236be994e4821e2e3fe5807f88ff7099ab3ce8973e4399ccb24bcb41c8d92c64675a32c77e7101"
        );
    }
}
