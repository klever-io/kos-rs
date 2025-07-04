use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// Stellar address encoding constants
const VERSION_BYTE_ACCOUNT_ID: u8 = 6 << 3; // 48 - Base32-encodes to 'G...'

pub struct Stellar {}

// CRC16 implementation for Stellar StrKey encoding
fn crc16_checksum(data: &[u8]) -> u16 {
    const POLY: u16 = 0x1021;
    let mut crc: u16 = 0x0000;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

// Stellar StrKey encoding function
fn stellar_encode(version: u8, src: &[u8]) -> Result<String, super::ChainError> {
    let payload_size = src.len();

    if payload_size > 32 {
        return Err(super::ChainError::InvalidPublicKey);
    }

    // Build raw data: version byte + src + 2 byte crc16
    let mut raw_data = Vec::with_capacity(1 + payload_size + 2);
    raw_data.push(version);
    raw_data.extend_from_slice(src);

    // Calculate CRC16 checksum
    let crc = crc16_checksum(&raw_data);
    raw_data.extend_from_slice(&crc.to_le_bytes());

    // Base32 encode using our internal base32 implementation
    let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &raw_data);

    // Remove padding for Stellar StrKey format
    let encoded = encoded.trim_end_matches('=').to_string();

    Ok(encoded)
}

impl Chain for Stellar {
    fn get_id(&self) -> u32 {
        6
    }

    fn get_name(&self) -> &str {
        "Stellar"
    }

    fn get_symbol(&self) -> &str {
        "XLM"
    }

    fn get_decimals(&self) -> u32 {
        7
    }

    fn mnemonic_to_seed(
        &self,
        mnemonic: alloc::string::String,
        password: alloc::string::String,
    ) -> Result<Vec<u8>, super::ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(
        &self,
        seed: Vec<u8>,
        path: alloc::string::String,
    ) -> Result<Vec<u8>, super::ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> alloc::string::String {
        format!("m/44'/{}'/{}'", 148, index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, super::ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<alloc::string::String, super::ChainError> {
        stellar_encode(VERSION_BYTE_ACCOUNT_ID, &public_key)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<super::Transaction, super::ChainError> {
        let sig = self.sign_raw(private_key, tx.tx_hash.clone())?;

        tx.signature = sig.as_slice().to_vec();
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, super::ChainError> {
        let sig = self.sign_raw(private_key.clone(), message.clone())?;

        // public key is not recoverable from signature. So append it to the signature
        let mut signature = sig;
        signature.extend_from_slice(&private_key);

        Ok(signature)
    }

    fn sign_raw(
        &self,
        private_key: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, super::ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let signature = Ed25519::sign(&pvk_bytes, &payload)?;
        pvk_bytes.fill(0);
        Ok(signature)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<super::TxInfo, super::ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> super::ChainType {
        ChainType::STELLAR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_address() {
        let stellar = Stellar {};

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();

        let path = stellar.get_path(0, false);
        let pbk = stellar.derive(seed, path).unwrap();

        let public_key = stellar.get_pbk(pbk).unwrap();

        let result = stellar.get_address(public_key);
        assert!(result.is_ok(), "get_address should succeed");

        let address = result.unwrap();
        assert!(!address.is_empty(), "Address should not be empty");
        assert!(
            address.starts_with('G'),
            "Stellar address should start with 'G'"
        );
        assert_eq!(
            address.len(),
            56,
            "Stellar address should be 56 characters long"
        );
    }
}
