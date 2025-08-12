use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[allow(clippy::upper_case_acronyms)]
pub struct SOL {}

impl Chain for SOL {
    fn get_id(&self) -> u32 {
        40
    }

    fn get_name(&self) -> &str {
        "Solana"
    }

    fn get_symbol(&self) -> &str {
        "SOL"
    }

    fn get_decimals(&self) -> u32 {
        9
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/501'/0'/0'/{index}'")
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

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let signature = self.sign_raw(private_key, tx.tx_hash.clone())?;
        let num_existing_signatures = tx.signature.len() / 64;

        if num_existing_signatures > 1 {
            let mut signatures = Vec::new();
            signatures.push(signature);

            for i in 0..num_existing_signatures {
                let start = i * 64;
                let end = start + 64;
                signatures.push(tx.signature[start..end].to_vec());
            }
            tx.signature = signatures.into_iter().flatten().collect();
        } else {
            tx.signature = signature;
        }

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        self.sign_raw(private_key, message)
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
        ChainType::SOL
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
        let path = sol.get_path(0, false);
        let pvk = sol.derive(seed, path).unwrap();
        let pbk = sol.get_pbk(pvk).unwrap();
        let addr = sol.get_address(pbk).unwrap();
        assert_eq!(addr, "B9sVeu4rJU12oUrUtzjc6BSNuEXdfvurZkdcaTVkP2LY");
    }

    #[test]
    fn test_sign_message() {
        let sol = SOL {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sol.derive(seed, "m/44'/501'/0'/0'/0'".to_string()).unwrap();

        let message = "test message".as_bytes().to_vec();
        let result = sol.sign_message(pvk.clone(), message, false).unwrap();

        // Same transaction signed with same key should produce same signature and hash
        assert_eq!(hex::encode(&result), "a3c211cc274707367d89ee4ecdab99fa99d856c4ccbc03591bddcaf325da2f3b64f74f4e692da212d3ce157bea6277195c66765e4f552c42ea63d513a07d8907");
    }
}
