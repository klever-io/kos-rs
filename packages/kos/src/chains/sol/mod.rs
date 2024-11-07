use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub struct SOL {}

impl Chain for SOL {
    fn get_name(&self) -> &str {
        "Solana"
    }

    fn get_symbol(&self) -> &str {
        "SOL"
    }

    fn get_decimals(&self) -> u32 {
        todo!()
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
            None => format!("m/44'/501'/0'/0'/{}'", index),
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let addr = b58enc(&public_key);
        Ok(String::from_utf8(addr)?)
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
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let sol = SOL {};
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = sol.get_path(0, None);
        let pvk = sol.derive(seed, path).unwrap();
        let pbk = sol.get_pbk(pvk).unwrap();
        let addr = sol.get_address(pbk).unwrap();
        assert_eq!(addr, "B9sVeu4rJU12oUrUtzjc6BSNuEXdfvurZkdcaTVkP2LY");
    }
}
