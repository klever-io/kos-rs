use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// Stellar address encoding constants
const VERSION_BYTE_ACCOUNT_ID: u8 = 6 << 3; // 48 - Base32-encodes to 'G...'
const VERSION_BYTE_SEED: u8 = 18 << 3; // 144 - Base32-encodes to 'S...'
const ED25519_KEY_SIZE: usize = 32;
const STELLAR_RAW_DATA_SIZE: usize = 35;

pub struct XLM {}

impl XLM {
    pub fn get_secret_key(&self, private_key: Vec<u8>) -> Result<String, super::ChainError> {
        let pvk_bytes: [u8; ED25519_KEY_SIZE] = private_key_from_vec(&private_key)?;
        stellar_encode_secret(&pvk_bytes)
    }

    pub fn decode_secret_key(&self, secret_key: &str) -> Result<Vec<u8>, super::ChainError> {
        let (version, payload) = stellar_decode(secret_key)?;

        if version != VERSION_BYTE_SEED {
            return Err(super::ChainError::InvalidPrivateKey);
        }

        Ok(payload)
    }

    pub fn decode_address(&self, address: &str) -> Result<Vec<u8>, super::ChainError> {
        let (version, payload) = stellar_decode(address)?;

        if version != VERSION_BYTE_ACCOUNT_ID {
            return Err(super::ChainError::InvalidPublicKey);
        }

        Ok(payload)
    }
}

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

    if payload_size != ED25519_KEY_SIZE {
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

    // Remove padding for Stellar StrKey format and convert to uppercase
    let encoded = encoded.trim_end_matches('=').to_uppercase();

    Ok(encoded)
}

fn stellar_encode_secret(secret_key: &[u8]) -> Result<String, super::ChainError> {
    stellar_encode(VERSION_BYTE_SEED, secret_key)
}

fn stellar_decode(encoded: &str) -> Result<(u8, Vec<u8>), super::ChainError> {
    let padded = match encoded.len() % 8 {
        0 => encoded.to_string(),
        n => format!("{}{}", encoded, "=".repeat(8 - n)),
    };

    let raw_data = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded)
        .ok_or(super::ChainError::InvalidPublicKey)?;

    if raw_data.len() != STELLAR_RAW_DATA_SIZE {
        return Err(super::ChainError::InvalidPublicKey);
    }

    let version = raw_data[0];
    let payload = &raw_data[1..33];
    let provided_checksum = u16::from_le_bytes([raw_data[33], raw_data[34]]);

    let calculated_checksum = crc16_checksum(&raw_data[0..33]);
    if provided_checksum != calculated_checksum {
        return Err(super::ChainError::InvalidPublicKey);
    }

    Ok((version, payload.to_vec()))
}

impl Chain for XLM {
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
        let sig = self.sign_raw(private_key.clone(), message)?;

        let pbk = self.get_pbk(private_key)?;

        // public key is not recoverable from signature. So append it to the signature
        let mut sig_with_pbk = Vec::new();

        sig_with_pbk.append(&mut sig.to_vec());
        sig_with_pbk.append(&mut pbk.to_vec());

        Ok(sig_with_pbk)
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
        ChainType::XLM
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::Transaction;
    use crate::test_utils::get_test_mnemonic;
    use alloc::vec;

    const STELLAR_KEY_LENGTH: usize = 56;
    const ED25519_SIG_SIZE: usize = 64;
    const COMBINED_SIG_SIZE: usize = 96;
    const INVALID_KEY_SIZE: usize = 33;

    #[test]
    fn test_xlm_derive() {
        let mnemonic = get_test_mnemonic();

        let seed = XLM {}.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let path = XLM {}.get_path(0, false);
        let pvk = XLM {}.derive(seed, path).unwrap();
        assert_eq!(pvk.len(), ED25519_KEY_SIZE);
        let pbk = XLM {}.get_pbk(pvk).unwrap();
        assert_eq!(pbk.len(), ED25519_KEY_SIZE);
        let addr = XLM {}.get_address(pbk).unwrap();
        assert!(addr.starts_with('G'));
        assert_eq!(addr.len(), STELLAR_KEY_LENGTH);
    }

    #[test]
    fn test_get_address() {
        let stellar = XLM {};

        let mnemonic = get_test_mnemonic();
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
            STELLAR_KEY_LENGTH,
            "Stellar address should be 56 characters long"
        );
    }

    #[test]
    fn test_get_address_with_different_index() {
        let stellar = XLM {};

        let mnemonic = get_test_mnemonic();
        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();

        let path = stellar.get_path(1, false);
        let pbk = stellar.derive(seed, path).unwrap();

        let public_key = stellar.get_pbk(pbk).unwrap();

        let result = stellar.get_address(public_key);
        assert!(result.is_ok(), "get_address should succeed");

        let address = result.unwrap();
        assert!(
            address.starts_with('G'),
            "Stellar address should start with 'G'"
        );
        assert_eq!(
            address.len(),
            STELLAR_KEY_LENGTH,
            "Stellar address should be 56 characters long"
        );
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = get_test_mnemonic();

        let chain = XLM {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let message = "test message".as_bytes().to_vec();

        let signature = chain.sign_message(pvk, message, false).unwrap();

        // Ed25519 signature is 64 bytes + 32 bytes public key = 96 bytes total
        assert_eq!(signature.len(), COMBINED_SIG_SIZE);

        // Verify the signature contains both signature and public key
        let sig_part = &signature[..ED25519_SIG_SIZE];
        let pubkey_part = &signature[ED25519_SIG_SIZE..];

        assert_eq!(sig_part.len(), ED25519_SIG_SIZE);
        assert_eq!(pubkey_part.len(), ED25519_KEY_SIZE);
    }

    #[test]
    fn test_sign_raw() {
        let mnemonic = get_test_mnemonic();

        let chain = XLM {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let payload = "test payload".as_bytes().to_vec();

        let signature = chain.sign_raw(pvk, payload).unwrap();

        assert_eq!(signature.len(), ED25519_SIG_SIZE);
    }

    #[test]
    fn test_sign_tx() {
        let mnemonic = get_test_mnemonic();

        let chain = XLM {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let tx_hash = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let tx = Transaction {
            raw_data: vec![],
            tx_hash,
            signature: vec![],
            options: None,
        };

        let signed_tx = chain.sign_tx(pvk, tx).unwrap();

        // Ed25519 signature should be 64 bytes
        assert_eq!(signed_tx.signature.len(), ED25519_SIG_SIZE);
    }

    #[test]
    fn test_get_path() {
        let chain = XLM {};

        let path0 = chain.get_path(0, false);
        assert_eq!(path0, "m/44'/148'/0'");

        let path1 = chain.get_path(1, false);
        assert_eq!(path1, "m/44'/148'/1'");

        let path10 = chain.get_path(10, false);
        assert_eq!(path10, "m/44'/148'/10'");
    }

    #[test]
    fn test_stellar_encode() {
        let valid_key = vec![1; ED25519_KEY_SIZE];
        let result = stellar_encode(VERSION_BYTE_ACCOUNT_ID, &valid_key);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert!(encoded.starts_with('G'));
        assert_eq!(encoded.len(), STELLAR_KEY_LENGTH);

        let invalid_key = vec![1; INVALID_KEY_SIZE];
        let result = stellar_encode(VERSION_BYTE_ACCOUNT_ID, &invalid_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChainError::InvalidPublicKey));
    }

    #[test]
    fn test_stellar_secret_key_encoding() {
        let stellar = XLM {};
        let mnemonic = get_test_mnemonic();

        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = stellar.get_path(0, false);
        let private_key = stellar.derive(seed, path).unwrap();

        let secret_key = stellar.get_secret_key(private_key.clone()).unwrap();

        assert!(
            secret_key.starts_with('S'),
            "Secret key should start with 'S'"
        );
        assert_eq!(
            secret_key.len(),
            STELLAR_KEY_LENGTH,
            "Secret key should be 56 characters long"
        );

        assert!(
            secret_key
                .chars()
                .all(|c| c.is_alphanumeric() && (!c.is_alphabetic() || c.is_uppercase())),
            "Secret key should be uppercase alphanumeric"
        );

        let decoded_private_key = stellar.decode_secret_key(&secret_key).unwrap();
        let original_private_key: [u8; ED25519_KEY_SIZE] =
            private_key_from_vec(&private_key).unwrap();
        assert_eq!(
            decoded_private_key,
            original_private_key.to_vec(),
            "Decoded secret key should match original"
        );
    }

    #[test]
    fn test_stellar_address_decoding() {
        let stellar = XLM {};
        let mnemonic = get_test_mnemonic();

        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = stellar.get_path(0, false);
        let private_key = stellar.derive(seed, path).unwrap();
        let public_key = stellar.get_pbk(private_key).unwrap();
        let address = stellar.get_address(public_key.clone()).unwrap();

        let decoded_public_key = stellar.decode_address(&address).unwrap();
        assert_eq!(
            decoded_public_key, public_key,
            "Decoded public key should match original"
        );
    }

    #[test]
    fn test_stellar_decode_invalid_inputs() {
        let stellar = XLM {};

        let invalid_secret = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; // G instead of S
        let result = stellar.decode_secret_key(invalid_secret);
        assert!(result.is_err());

        let invalid_address = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; // S instead of G
        let result = stellar.decode_address(invalid_address);
        assert!(result.is_err());

        let invalid_format = "invalid_string";
        let result = stellar.decode_secret_key(invalid_format);
        assert!(result.is_err());
    }

    #[test]
    fn test_stellar_secret_key_validation() {
        let stellar = XLM {};
        let mnemonic = get_test_mnemonic();

        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = stellar.get_path(0, false);
        let private_key = stellar.derive(seed, path).unwrap();

        let secret_key_encoded = stellar.get_secret_key(private_key.clone()).unwrap();
        let decoded_private_key = stellar.decode_secret_key(&secret_key_encoded).unwrap();

        let public_key_from_decoded = stellar.get_pbk(decoded_private_key).unwrap();
        let original_public_key = stellar.get_pbk(private_key).unwrap();

        assert_eq!(
            public_key_from_decoded, original_public_key,
            "Public key derived from decoded secret key should match original"
        );
    }

    #[test]
    fn test_stellar_keypair_consistency() {
        let stellar = XLM {};
        let mnemonic = get_test_mnemonic();

        let seed = stellar
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = stellar.get_path(0, false);
        let private_key = stellar.derive(seed, path).unwrap();

        let secret_key = stellar.get_secret_key(private_key.clone()).unwrap();
        let public_key = stellar.get_pbk(private_key).unwrap();
        let address = stellar.get_address(public_key).unwrap();

        assert!(secret_key.starts_with('S'));
        assert!(address.starts_with('G'));
        assert_eq!(secret_key.len(), STELLAR_KEY_LENGTH);
        assert_eq!(address.len(), STELLAR_KEY_LENGTH);

        let decoded_secret = stellar.decode_secret_key(&secret_key).unwrap();
        let derived_public = stellar.get_pbk(decoded_secret).unwrap();
        let derived_address = stellar.get_address(derived_public).unwrap();

        assert_eq!(
            derived_address, address,
            "Address derived from secret key should match original address"
        );
    }

    #[test]
    fn test_specific_stellar_secret_key() {
        let stellar = XLM {};
        const TEST_STELLAR_SECRET_KEY: &str =
            "SBTEMPAKHZLJWSNGNXQWW2WHUH6PZP5W26OCFCSO554FT7DHXUKA32KK";
        const TEST_STELLAR_ADDRESS: &str =
            "GCRRSYF5JBFPXHN5DCG65A4J3MUYE53QMQ4XMXZ3CNKWFJIJJTGMH6MZ";

        let decoded_bytes = stellar.decode_secret_key(TEST_STELLAR_SECRET_KEY).unwrap();
        assert_eq!(
            decoded_bytes.len(),
            ED25519_KEY_SIZE,
            "Decoded secret should be 32 bytes"
        );

        let public_key = stellar.get_pbk(decoded_bytes).unwrap();
        assert_eq!(
            public_key.len(),
            ED25519_KEY_SIZE,
            "Public key should be 32 bytes"
        );

        let address = stellar.get_address(public_key).unwrap();
        assert!(address.starts_with('G'), "Address should start with 'G'");
        assert_eq!(
            address.len(),
            STELLAR_KEY_LENGTH,
            "Address should be 56 characters"
        );

        assert_eq!(address, TEST_STELLAR_ADDRESS);
    }
}
