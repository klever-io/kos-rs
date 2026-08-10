mod util;

use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::{b58dec, b58enc_string};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const ID: u32 = 64;

/// NEAR Protocol native chain implementation.
///
/// - Key scheme: Ed25519 (SLIP-44 coin type 397)
/// - Derivation path: `m/44'/397'/{index}'` (hardened)
/// - Address format: 64-char lowercase hex of the Ed25519 public key (implicit account)
/// - Transaction signing: Ed25519 signature over `tx_hash`
#[allow(clippy::upper_case_acronyms)]
pub struct NEAR {}

impl Chain for NEAR {
    fn get_id(&self) -> u32 {
        ID
    }

    fn get_name(&self) -> &str {
        "Near"
    }

    fn get_symbol(&self) -> &str {
        "NEAR"
    }

    /// NEAR uses yoctoNEAR as base unit (1 NEAR = 10^24 yoctoNEAR).
    fn get_decimals(&self) -> u32 {
        24
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    /// Derives an Ed25519 private key using SLIP-0010 hardened derivation.
    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let private_key = bip32::derive_ed25519(&seed, path)?;
        let public_key = Ed25519::public_from_private(&private_key)?;

        let mut data_to_encode = Vec::new();
        data_to_encode.extend_from_slice(&private_key);
        data_to_encode.extend_from_slice(&public_key);

        let data_base58 = b58enc_string(&data_to_encode);
        let data_with_schema = format!("{}:{data_base58}", util::NearKeySchema::Ed25519);
        Ok(data_with_schema.into_bytes())
    }

    /// Standard NEAR BIP-44 path: `m/44'/397'/{index}'`.
    /// Coin type 397 is the SLIP-44 registered value for NEAR Protocol.
    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/397'/{index}'")
    }

    /// Expects private key in `<schema>:<pvk+pbk_base58>` format and returns public key in `<schema>:<pbk_base58>` format.
    /// Rejects unsupported key schemas (secp256k1 and ml-dsa-65).
    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let s = core::str::from_utf8(&private_key).map_err(|_| ChainError::InvalidPrivateKey)?;
        let trimmed = s.trim();

        let (schema, pvk_base58) =
            util::NearKeySchema::parse_prefix(trimmed).ok_or(ChainError::InvalidPrivateKey)?;

        match schema {
            util::NearKeySchema::Secp256k1 | util::NearKeySchema::MlDsa65 => {
                Err(ChainError::NotSupported)
            }
            util::NearKeySchema::Ed25519 => {
                let decoded_bytes =
                    b58dec(pvk_base58.as_bytes()).map_err(|_| ChainError::InvalidPrivateKey)?;

                let mut pvk_bytes = private_key_from_vec(&decoded_bytes)?;
                let pbk = Ed25519::public_from_private(&pvk_bytes)?;
                pvk_bytes.fill(0);

                let pbk_base58 = b58enc_string(&pbk);
                let pbk_with_schema = format!("{schema}:{pbk_base58}");
                Ok(pbk_with_schema.into_bytes())
            }
        }
    }

    /// Encodes the Ed25519 public key in `<schema>:<public_key_base58>` format as a 64-char lowercase hex string.
    /// Rejects unsupported key schemas (secp256k1 and ml-dsa-65).
    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let s = core::str::from_utf8(&public_key).map_err(|_| ChainError::InvalidPublicKey)?;
        let trimmed = s.trim();

        let (schema, pbk_base58) =
            util::NearKeySchema::parse_prefix(trimmed).ok_or(ChainError::InvalidPublicKey)?;

        match schema {
            util::NearKeySchema::Secp256k1 | util::NearKeySchema::MlDsa65 => {
                Err(ChainError::NotSupported)
            }
            util::NearKeySchema::Ed25519 => {
                let pbk_bytes =
                    b58dec(pbk_base58.as_bytes()).map_err(|_| ChainError::InvalidPublicKey)?;

                if pbk_bytes.len() != 32 {
                    return Err(ChainError::InvalidPublicKey);
                }

                Ok(hex::encode(&pbk_bytes))
            }
        }
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let signature = self.sign_raw(private_key, tx.tx_hash.clone())?;
        tx.signature = signature;
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        let sig = self.sign_raw(private_key.clone(), message)?;
        let pbk = self.get_pbk(private_key)?;

        // Ed25519 public key is not recoverable from the signature alone,
        // so we append it – consistent with APT/XLM pattern in this codebase.
        let mut sig_with_pbk = Vec::new();
        sig_with_pbk.extend_from_slice(&sig);
        sig_with_pbk.extend_from_slice(&pbk);

        Ok(sig_with_pbk)
    }

    /// Expects private key in `<schema>:<pvk+pbk_base58>` format.
    /// Rejects unsupported key schemas (secp256k1 and ml-dsa-65).
    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let s = core::str::from_utf8(&private_key).map_err(|_| ChainError::InvalidPrivateKey)?;
        let trimmed = s.trim();

        let (schema, pvk_base58) =
            util::NearKeySchema::parse_prefix(trimmed).ok_or(ChainError::InvalidPrivateKey)?;

        match schema {
            util::NearKeySchema::Secp256k1 | util::NearKeySchema::MlDsa65 => {
                Err(ChainError::NotSupported)
            }
            util::NearKeySchema::Ed25519 => {
                let decoded_bytes =
                    b58dec(pvk_base58.as_bytes()).map_err(|_| ChainError::InvalidPrivateKey)?;

                let mut pvk_bytes = private_key_from_vec(&decoded_bytes)?;
                let signature = Ed25519::sign(&pvk_bytes, &payload)?;
                pvk_bytes.fill(0);
                Ok(signature)
            }
        }
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::NEAR
    }

    fn decode_private_key(&self, private_key: String) -> Result<Vec<u8>, ChainError> {
        Ok(private_key.as_bytes().to_vec())
    }

    fn decode_public_key(&self, public_key: String) -> Result<Vec<u8>, ChainError> {
        Ok(public_key.as_bytes().to_vec())
    }

    fn encode_private_key(&self, private_key: Vec<u8>) -> String {
        String::from_utf8_lossy(&private_key).to_string()
    }

    fn encode_public_key(&self, public_key: Vec<u8>) -> String {
        String::from_utf8_lossy(&public_key).to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chains::Transaction;
    use crate::test_utils::get_test_mnemonic;
    use alloc::string::ToString;
    use alloc::vec;
    use core::assert_eq;

    fn get_near() -> NEAR {
        NEAR {}
    }

    fn derive_key(near: &NEAR) -> Vec<u8> {
        let mnemonic = get_test_mnemonic().to_string();
        let seed = near.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let path = near.get_path(0, false);
        near.derive(seed, path).unwrap()
    }

    #[test]
    fn test_get_path() {
        let near = get_near();
        assert_eq!(near.get_path(0, false), "m/44'/397'/0'");
        assert_eq!(near.get_path(1, false), "m/44'/397'/1'");
        assert_eq!(near.get_path(5, false), "m/44'/397'/5'");
    }

    #[test]
    fn test_derive_and_address() {
        let near = get_near();
        let pvk_bytes = derive_key(&near);
        let pvk_str = String::from_utf8(pvk_bytes.clone()).unwrap();
        assert!(pvk_str.starts_with("ed25519:"));

        let pbk_bytes = near.get_pbk(pvk_bytes.clone()).unwrap();
        let pbk_str = String::from_utf8(pbk_bytes.clone()).unwrap();
        assert!(pbk_str.starts_with("ed25519:"));

        let addr = near.get_address(pbk_bytes).unwrap();

        // NEAR implicit account: exactly 64 lowercase hex chars
        assert_eq!(addr.len(), 64);
        assert!(
            addr.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "Address must be lowercase hex"
        );
        assert_eq!(
            addr,
            "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412"
        );
    }

    #[test]
    fn test_generate_address_from_public_key() {
        let near = get_near();

        // Valid public key derived from test mnemonic
        let pvk_bytes = derive_key(&near);
        let pbk_bytes = near.get_pbk(pvk_bytes).unwrap();
        let addr = near.get_address(pbk_bytes).unwrap();

        assert_eq!(addr.len(), 64);
        assert!(
            addr.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "Address must be lowercase hex"
        );

        // Known raw 32-byte public key (all 0x01 bytes)
        let raw_pubkey = vec![1u8; 32];
        let pbk_b58 = b58enc_string(&raw_pubkey);
        let pbk_formatted = format!("ed25519:{pbk_b58}").into_bytes();
        let addr_from_known = near.get_address(pbk_formatted).unwrap();
        assert_eq!(
            addr_from_known,
            "0101010101010101010101010101010101010101010101010101010101010101"
        );

        // Known raw 32-byte public key (all 0x00 bytes -> base58 "11111111111111111111111111111111")
        let pbk_zeros = "ed25519:11111111111111111111111111111111"
            .as_bytes()
            .to_vec();
        let addr_zeros = near.get_address(pbk_zeros).unwrap();
        assert_eq!(
            addr_zeros,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // Invalid key length (decoded length != 32 bytes)
        let short_key = format!("ed25519:{}", b58enc_string(&[1u8; 31])).into_bytes();
        assert!(matches!(
            near.get_address(short_key),
            Err(ChainError::InvalidPublicKey)
        ));

        // Invalid UTF-8 sequence
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        assert!(matches!(
            near.get_address(invalid_utf8),
            Err(ChainError::InvalidPublicKey)
        ));
    }

    #[test]
    fn test_decode_private_key() {
        let near = get_near();
        let pvk_with_schema = derive_key(&near);
        let pvk_str = String::from_utf8(pvk_with_schema).unwrap();

        let decoded_pvk = near.decode_private_key(pvk_str.clone()).unwrap();
        assert_eq!(decoded_pvk.len(), pvk_str.len());
    }

    #[test]
    fn test_get_address_invalid_pubkey() {
        let near = get_near();

        // Key without schema prefix should fail
        let no_prefix = "99466004b85a739b8a90f79cde97a1901d1b7e86687161b30c3ad08b9389274f"
            .as_bytes()
            .to_vec();
        assert!(near.get_address(no_prefix).is_err());

        // Invalid base58 should fail
        let invalid_b58 = "ed25519:invalid_base58!!!".as_bytes().to_vec();
        assert!(near.get_address(invalid_b58).is_err());

        // Unsupported schemas should fail with NotSupported
        let secp_key = "secp256k1:somekey".as_bytes().to_vec();
        assert!(matches!(
            near.get_address(secp_key),
            Err(ChainError::NotSupported)
        ));

        let mldsa_key = "ml-dsa-65:somekey".as_bytes().to_vec();
        assert!(matches!(
            near.get_address(mldsa_key),
            Err(ChainError::NotSupported)
        ));
    }

    #[test]
    fn test_sign_raw() {
        let near = get_near();
        let pvk = derive_key(&near);

        let payload = "test payload".as_bytes().to_vec();
        let signature = near.sign_raw(pvk, payload).unwrap();

        // Ed25519 signature is always 64 bytes
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_sign_message() {
        let near = get_near();
        let pvk = derive_key(&near);

        let message = "test message".as_bytes().to_vec();
        let result = near.sign_message(pvk, message, false).unwrap();

        // 64-byte signature + ed25519:<pbk_base58>
        assert!(result.len() > 64);
        let sig_part = &result[..64];
        let pubkey_part = core::str::from_utf8(&result[64..]).unwrap();
        assert_eq!(sig_part.len(), 64);
        assert!(pubkey_part.starts_with("ed25519:"));
    }

    #[test]
    fn test_sign_tx() {
        let near = get_near();
        let pvk = derive_key(&near);

        let tx = Transaction {
            raw_data: vec![],
            tx_hash: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            signature: vec![],
            options: None,
        };

        let signed = near.sign_tx(pvk, tx).unwrap();
        assert_eq!(signed.signature.len(), 64);
    }

    #[test]
    fn test_deterministic_signing() {
        let near = get_near();
        let pvk = derive_key(&near);

        let message = "determinism check".as_bytes().to_vec();

        let sig1 = near.sign_raw(pvk.clone(), message.clone()).unwrap();
        let sig2 = near.sign_raw(pvk, message).unwrap();

        // Ed25519 is deterministic – same key + message must produce same signature
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_chain_metadata() {
        let near = get_near();
        assert_eq!(near.get_id(), ID);
        assert_eq!(near.get_name(), "Near");
        assert_eq!(near.get_symbol(), "NEAR");
        assert_eq!(near.get_decimals(), 24);
        assert_eq!(near.get_chain_type(), ChainType::NEAR);
    }
}
