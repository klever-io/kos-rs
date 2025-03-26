mod models;

use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::sha3_digest;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[allow(clippy::upper_case_acronyms)]
pub struct APT {}

impl Chain for APT {
    fn get_id(&self) -> u32 {
        50
    }

    fn get_name(&self) -> &str {
        "Aptos"
    }

    fn get_symbol(&self) -> &str {
        "APT"
    }

    fn get_decimals(&self) -> u32 {
        8
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/637'/0'/0'/{}'", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, mut public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 32 {
            return Err(ChainError::InvalidPublicKey);
        }

        public_key.push(0);
        let checksum = sha3_digest(&public_key[..]);
        let hex_encode = hex::encode(checksum);
        let mut addr = "0x".to_string();
        addr.push_str(&hex_encode[..64]);
        Ok(addr)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        if private_key.is_empty() {
            return Err(ChainError::InvalidPrivateKey);
        }

        let specific_str =
            String::from_utf8(tx.raw_data.clone()).map_err(|_| ChainError::DecodeRawTx)?;

        let mut specific: TxSpecific =
            tiny_json_rs::decode(specific_str).map_err(|_| ChainError::DecodeRawTx)?;

        let signing_message = hex::decode(specific.signing_message.trim_start_matches("0x"))
            .map_err(|_| ChainError::ProtoDecodeError)?;

        let signature = self.sign_raw(private_key.clone(), signing_message)?;

        let public_key = self.get_pbk(private_key)?;

        let signature_hex = format!("0x{}", hex::encode(&signature));
        let public_key_hex = format!("0x{}", hex::encode(&public_key));

        let transaction_signature = models::AptosSignature {
            r#type: "ed25519_signature".to_string(),
            public_key: public_key_hex,
            signature: signature_hex.clone(),
        };

        specific.transaction.signature = Some(transaction_signature);

        let specific_json = tiny_json_rs::encode(specific);
        tx.raw_data = specific_json.as_bytes().to_vec();
        tx.signature = signature_hex.as_bytes().to_vec();

        Ok(tx)
    }

    fn sign_message(
        &self,
        _private_key: Vec<u8>,
        _message: Vec<u8>,
    ) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let signature = Ed25519::sign(&pvk_bytes, &payload)?;

        pvk_bytes.fill(0);
        Ok(signature)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::APT
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::{String, ToString};

    #[test]
    fn test_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let apt = super::APT {};
        let seed = apt.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let pvk = apt
            .derive(seed.clone(), "m/44'/637'/0'/0'/0'".to_string())
            .unwrap();
        let pbk = apt.get_pbk(pvk.clone()).unwrap();
        let addr = apt.get_address(pbk.clone()).unwrap();
        assert_eq!(
            addr,
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf"
        );
    }
}
