use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::keccak256_digest;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use bech32::{u5, Variant};

pub struct EGLD {}

impl Chain for EGLD {
    fn get_name(&self) -> &str {
        "Elrond"
    }

    fn get_symbol(&self) -> &str {
        "EGLD"
    }

    fn get_decimals(&self) -> u32 {
        18
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
            None => format!("m/44'/508'/0'/0'/{}'", index),
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let pbk_hash = keccak256_digest(&public_key[..]);
        let add_encoded = bech32::convert_bits(pbk_hash.as_ref(), 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::new();
        for i in add_encoded {
            addr_u5.push(u5::try_from_u8(i)?);
        }
        let res = bech32::encode("erd", addr_u5, Variant::Bech32)?;
        Ok(res)
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

        let egld = super::EGLD {};
        let seed = egld.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let path = egld.get_path(0, None);
        let pvk = egld.derive(seed.clone(), path).unwrap();
        let pbk = egld.get_pbk(pvk.clone()).unwrap();
        let addr = egld.get_address(pbk.clone()).unwrap();
        assert_eq!(
            addr,
            "erd19a76e058k023kss9zhg5zfwtc9m8qwnq0tq8v3cp9e0632q9437sxrxrec"
        );
    }
}
