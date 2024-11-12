use crate::chains::eth::ETH;
use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction};
use crate::crypto::hash::keccak256_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::crypto::{bip32, secp256k1};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct MOVR {
    name: String,
    symbol: String,
    decimals: u32,
}

impl MOVR {
    pub fn new() -> Self {
        MOVR {
            name: "Moonriver".to_string(),
            symbol: "MOVR".to_string(),
            decimals: 18,
        }
    }

    pub fn new_glmr() -> Self {
        MOVR {
            name: "Moonbeam".to_string(),
            symbol: "GLMR".to_string(),
            decimals: 18,
        }
    }
}

impl Chain for MOVR {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_symbol(&self) -> &str {
        &self.symbol
    }

    fn get_decimals(&self) -> u32 {
        self.decimals
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk = private_key_from_vec(&private_key)?;

        let pbk = Secp256K1::private_to_public_uncompressed(&pvk)?;
        Ok(Vec::from(pbk))
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let pbk_hash = keccak256_digest(&public_key[1..]);
        let mut address_bytes: [u8; crate::chains::eth::ETH_ADDR_SIZE] =
            [0; crate::chains::eth::ETH_ADDR_SIZE];
        address_bytes.copy_from_slice(&pbk_hash[12..]);

        return ETH::addr_bytes_to_string(address_bytes);
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let tx_bytes = tx.raw_data.clone();
        let tx_hash = keccak256_digest(&tx_bytes);

        let sig = self.sign_raw(private_key, tx_hash.clone().to_vec())?;
        tx.signature = sig;
        tx.tx_hash = tx_hash.to_vec();

        Ok(tx)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = secp256k1::Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pvk_bytes: [u8; 32] = [0; 32];
        pvk_bytes.copy_from_slice(&private_key[..32]);

        let mut payload_bytes: [u8; 32] = [0; 32];
        payload_bytes.copy_from_slice(&message[..32]);

        let sig = secp256k1::Secp256K1::sign(&payload_bytes, &pvk_bytes)?;
        Ok(sig.to_vec())
    }

    fn get_tx_info(
        &self,
        _raw_tx: Vec<u8>,
    ) -> Result<crate::chains::TxInfo, crate::chains::ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_path(&self, index: u32, custom_path: Option<String>) -> String {
        match custom_path {
            Some(path) => path,
            None => format!("m/44'/60'/0'/0/{}", index), // Verify this path
        }
    }

    fn get_id(&self) -> u32 {
        32
    }
}
