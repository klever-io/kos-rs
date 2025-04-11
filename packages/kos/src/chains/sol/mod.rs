mod models;

use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use alloc::format;
use alloc::string::String;
use alloc::vec;
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
        format!("m/44'/501'/0'/0'/{}'", index)
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
        let mut sol_tx = models::SolanaTransaction::decode(&tx.raw_data)?;

        if sol_tx.message.header.num_required_signatures as usize != 1 {
            return Err(ChainError::InvalidTransactionHeader);
        }
        if sol_tx.message.account_keys.is_empty() {
            return Err(ChainError::InvalidAccountLength);
        }
        if sol_tx.message.recent_blockhash.iter().all(|&x| x == 0)
            || sol_tx.message.recent_blockhash.iter().all(|&x| x == 1)
        {
            return Err(ChainError::InvalidBlockhash);
        }

        let message_bytes = sol_tx.message.encode()?;

        let signature = self.sign_raw(private_key, message_bytes)?;
        if signature.len() != 64 {
            return Err(ChainError::InvalidSignatureLength);
        }
        sol_tx.signatures = vec![signature.clone()];

        tx.tx_hash = sol_tx.signatures[0].clone();

        let signed_tx = sol_tx.encode()?;

        tx.raw_data = signed_tx;
        tx.signature = signature;
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
    use crate::crypto::base64::simple_base64_decode;
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

    fn create_test_transaction() -> Vec<u8> {
        let tx = models::SolanaTransaction {
            message: models::Message {
                version: "legacy".to_string(),
                header: models::MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 0,
                },
                account_keys: vec![
                    vec![1; 32], // Sender
                    vec![2; 32], // Recipient
                    vec![3; 32], // Program ID
                ],
                recent_blockhash: [42; 32],
                instructions: vec![models::CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![0, 1],
                    data: vec![2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0], // Transfer 100 lamports
                }],
                address_table_lookups: vec![],
            },
            signatures: vec![],
        };
        tx.encode().unwrap()
    }

    #[test]
    fn test_derive_and_sign_tx() {
        let sol = SOL {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sol.derive(seed, "m/44'/501'/0'/0'/0'".to_string()).unwrap();

        let raw_tx = create_test_transaction();
        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let result = sol.sign_tx(pvk, tx).unwrap();

        assert_eq!(result.signature.len(), 64);

        // Verify tx_hash is not all ones and matches signature
        assert!(!result.tx_hash.iter().all(|&x| x == 1));
        assert_eq!(result.tx_hash.len(), 64);
        assert!(!result.tx_hash.iter().all(|&x| x == 1));
        assert!(!result.tx_hash.iter().all(|&x| x == 0));

        let decoded = models::SolanaTransaction::decode(&result.raw_data).unwrap();
        assert_eq!(decoded.signatures.len(), 1);
        assert_eq!(decoded.signatures[0], result.signature);
        assert_eq!(decoded.message.header.num_required_signatures, 1);
    }

    #[test]
    fn test_sign_tx_consistent_hash() {
        let sol = SOL {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sol.derive(seed, "m/44'/501'/0'/0'/0'".to_string()).unwrap();

        let raw_tx = create_test_transaction();
        let tx1 = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let tx2 = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let result1 = sol.sign_tx(pvk.clone(), tx1).unwrap();
        let result2 = sol.sign_tx(pvk, tx2).unwrap();

        // Same transaction signed with same key should produce same signature and hash
        assert_eq!(result1.signature, result2.signature);
        assert_eq!(result1.tx_hash, result2.tx_hash);
    }

    #[test]
    fn test_sign_tx_legacy() {
        let sol = SOL {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sol.derive(seed, "m/44'/501'/0'/0'/0'".to_string()).unwrap();

        let raw_tx = simple_base64_decode("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIEmjxocK65Bo8r+e3cj7GbPVedpCwx+DCZJ57Tw3fMN0e5dTAYLc651CwBwFga8GLJTsriJc/FAP3GlbhfEGOidAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAACg2vm5+lhfRud/PKY6hEMgdKkQ8I7jtpxDFjknIKRXGQMDAAUCSQIAAAMACQOAlpgAAAAAAAICAAEUAgAAAAEAAAAAAAAAsmBySL6HLBg=").unwrap();

        let tx1 = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let result = sol.sign_tx(pvk.clone(), tx1).unwrap();

        // Same transaction signed with same key should produce same signature and hash
        assert_eq!(hex::encode(&result.signature), "b079c666c9ff53bb26d7606d10131ebbc8d398dac9fd1285d5138bbdd521758d7a6b6bdb2876730637704eb1511f3f7d842343b9e406bb3e3583d6588949a904");
    }

    #[test]
    fn test_sign_tx_v0() {
        let sol = SOL {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = sol.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sol.derive(seed, "m/44'/501'/0'/0'/0'".to_string()).unwrap();

        let raw_tx = simple_base64_decode("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQAGCpo8aHCuuQaPK/nt3I+xmz1XnaQsMfgwmSee08N3zDdHWO9nf7VjXmRzcktw4WtkBVQDTqR6HHs/zYiFPEFdMlR2uAUKvCmGoT5EOvm/TqTTENr0znYcEsWsViKudXw20rGZQgJtALiRcUwlRMT2kZt8QRbvckZEPIiyFe59326vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACsH4P9uc5VDeldVYzceVRhzPQ3SsaI7BOphAAiCnjaBgMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAtD/6J/XX9kp0wJsfKVh53ksJqzbfyd1RSzIap7OM5egEedVb8jHAbu50xW7OaBUH/bGy3qP0jlECsc2iVrwTjwbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpheXoR6gYqo7X4aA9Sx2/Qcpf6TpzF6ddVuj771s5eWQFBgAFAua+AQAGAAkDRJEGAAAAAAAIBQMAEwkECZPxe2T0hK52/wgYCQACAwgTAQcIDxELAAIDDgoNDAkSEhAFI+UXy5d6460qAQAAABlkAAH4LgEAAAAAAMGtCQAAAAAAKwAFCQMDAAABCQEP5d+hcffknhCj1qkbVbtXFKZDtelOHlry/os01b5PsgXi4ePoyQXn5ODlRQ==").unwrap();
        let tx1 = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let result = sol.sign_tx(pvk.clone(), tx1).unwrap();
        // Same transaction signed with same key should produce same signature and hash
        assert_eq!(hex::encode(&result.signature), "40098643a37209b2e0984c2f55872ccf150c44a1100a16a985b1bc04b13c31f9d9d1b070229241df5aaa21af22e0e4f88b6371106766fd95096b67f1066f8701");
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
