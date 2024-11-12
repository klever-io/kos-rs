use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::hash::ripemd160_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use bech32::{u5, Variant};

const BNB_PREFIX: &str = "bnb";

pub struct BNB {}

impl Chain for BNB {
    fn get_id(&self) -> u32 {
        17
    }

    fn get_name(&self) -> &str {
        "Binance"
    }

    fn get_symbol(&self) -> &str {
        "BNB"
    }

    fn get_decimals(&self) -> u32 {
        todo!()
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_path(&self, index: u32, custom_path: Option<String>) -> String {
        match custom_path {
            Some(path) => path,
            None => format!("m/44'/714'/0'/0/{}", index),
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;

        let pbk = Secp256K1::private_to_public_compressed(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk.to_vec())
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);
        let add_encoded = bech32::convert_bits(&hash, 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::new();
        for i in add_encoded {
            addr_u5.push(u5::try_from_u8(i)?);
        }
        let res = bech32::encode(BNB_PREFIX, addr_u5, Variant::Bech32)?;
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
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
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
    fn test_mnemonic_to_seed() {
        let bnb = BNB {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = bnb.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = bnb.get_path(0, None);
        let pvk = bnb.derive(seed, path).unwrap();
        let pbk = bnb.get_pbk(pvk.clone()).unwrap();

        let addr = bnb.get_address(pbk.clone()).unwrap();

        assert_eq!(addr, "bnb1rxhz5vdv4fvdjye8gxqvfv0yvg20jtlwf4f38d");
    }
}
