use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::sha3_digest;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct APT {}

impl Chain for APT {
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

    fn get_path(&self, index: u32, custom_path: Option<String>) -> String {
        match custom_path {
            Some(path) => path,
            None => format!("m/44'/637'/0'/0'/{}'", index),
        }
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

    fn sign_tx(&self, _private_key: Vec<u8>, _tx: Transaction) -> Result<Transaction, ChainError> {
        Err(ChainError::NotSupported)
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
