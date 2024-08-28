use hex::FromHexError;
use hex::ToHex;

use kos_crypto::cipher;
use kos_crypto::cipher::CipherAlgo;
use kos_sdk::chain::Chain;
use kos_sdk::models::PathOptions;
use kos_sdk::wallet::Wallet;
use kos_types::error::Error as KosError;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
enum KOSError {
    #[error("UnsupportedChainError: Unsupported chain {id}")]
    UnsupportedChain { id: String },
    #[error("KOSDelegateError: {0}")]
    KOSDelegate(String),
    #[error("HexDecodeError: {0}")]
    HexDecode(String),
}

impl From<KosError> for KOSError {
    fn from(err: KosError) -> Self {
        KOSError::KOSDelegate(err.to_string())
    }
}

impl From<FromHexError> for KOSError {
    fn from(err: FromHexError) -> Self {
        KOSError::HexDecode(err.to_string())
    }
}

#[derive(uniffi::Record)]
struct KOSAccount {
    pub chain_id: i32,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub path: String,
}

#[uniffi::export]
fn generate_mnemonic(size: i32) -> Result<String, KOSError> {
    Ok(kos_crypto::mnemonic::generate_mnemonic(size as usize)?.to_phrase())
}

#[uniffi::export]
fn validate_mnemonic(mnemonic: String) -> bool {
    kos_crypto::mnemonic::validate_mnemonic(mnemonic.as_str()).is_ok()
}

#[uniffi::export]
fn generate_wallet_from_mnemonic(
    mnemonic: String,
    chain_id: i32,
    index: i32,
    use_legacy_path: bool,
) -> Result<KOSAccount, KOSError> {
    let chain = get_chain_by(chain_id)?;
    let mut path_options = PathOptions::new(index as u32);
    path_options.set_legacy(use_legacy_path);
    let path = chain.get_path(&path_options)?;
    let wallet = Wallet::from_mnemonic(chain, mnemonic, path, None)?;
    Ok(KOSAccount {
        chain_id,
        private_key: wallet.get_private_key(),
        public_key: wallet.get_public_key(),
        address: wallet.get_address(),
        path: wallet.get_path(),
    })
}

#[uniffi::export]
fn generate_wallet_from_private_key(
    chain_id: i32,
    private_key: String,
) -> Result<KOSAccount, KOSError> {
    let chain = get_chain_by(chain_id)?;
    let wallet = Wallet::from_private_key(chain, private_key)?;
    Ok(KOSAccount {
        chain_id,
        private_key: wallet.get_private_key(),
        public_key: wallet.get_public_key(),
        address: wallet.get_address(),
        path: wallet.get_path(),
    })
}

#[uniffi::export]
fn encrypt_with_gmc(data: String, password: String) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::GMC.encrypt(data.as_bytes(), password.as_str())?;
    Ok(encrypted_data.encode_hex())
}

#[uniffi::export]
fn encrypt_with_cbc(data: String, password: String) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::CBC.encrypt(data.as_bytes(), password.as_str())?;
    Ok(encrypted_data.encode_hex())
}

#[uniffi::export]
fn encrypt_with_cfb(data: String, password: String) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::CFB.encrypt(data.as_bytes(), password.as_str())?;
    Ok(encrypted_data.encode_hex())
}

#[uniffi::export]
fn decrypt(data: String, password: String) -> Result<String, KOSError> {
    let data_in_byte = hex::decode(data)?;
    let decrypted_data = cipher::decrypt(&data_in_byte, password.as_str())?;
    Ok(String::from_utf8_lossy(&decrypted_data).to_string())
}

fn get_chain_by(id: i32) -> Result<Chain, KOSError> {
    let id_u8 = u8::try_from(id).map_err(|_| KOSError::UnsupportedChain { id: id.to_string() })?;
    let chain = Chain::get_by_code(id_u8)
        .ok_or_else(|| KOSError::UnsupportedChain { id: id.to_string() })?;
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn should_generate_mnemonic() {
        let size = 12;
        match generate_mnemonic(size) {
            Ok(mnemonic) => assert!(!mnemonic.is_empty(), "The mnemonic should not be empty"),
            Err(_) => panic!("unexpected error!"),
        }
    }

    #[test]
    fn should_fail_to_generate_mnemonic() {
        let size = -1;
        match generate_mnemonic(size) {
            Ok(_) => panic!("A error was expected but found a mnemonic"),
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), "Invalid error"),
        }
    }

    #[test]
    fn should_validate_mnemonic_with_success() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let result = validate_mnemonic(mnemonic);
        assert!(result, "The mnemonic should be valid")
    }

    #[test]
    fn should_validate_mnemonic_with_failure() {
        let mnemonic = "abandon xxx abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let result = validate_mnemonic(mnemonic);
        assert!(!result, "The mnemonic should be not valid")
    }

    #[test]
    fn should_fail_to_get_account_from_mnemonic_with_invalid_chain() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let index = 0;
        let chain_id = 999;
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, false) {
            Ok(_) => panic!("A error was expected but found a mnemonic"),
            Err(e) => {
                if let KOSError::UnsupportedChain { id } = e {
                    assert_eq!(id, chain_id.to_string(), "Invalid error");
                } else {
                    panic!("Expected UnsupportedChainError but found different error");
                }
            }
        }
    }

    #[test]
    fn should_get_account_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let index = 0;
        let chain_id = 38;
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, false) {
            Ok(account) => {
                assert_eq!(
                    account.address,
                    "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
                    "The address doesn't match"
                );
                assert_eq!(
                    account.private_key,
                    "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d".to_string(),
                    "The private_key doesn't match"
                );
                assert_eq!(account.chain_id, chain_id, "The chain_id doesn't match");
            }
            Err(_) => panic!("unexpected error!"),
        }
    }

    #[test]
    fn should_get_all_supported_chains_account_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let index = 0;
        for (&chain_code, _) in Chain::get_chains().iter() {
            println!("code = {}", chain_code)
        }
        for (&chain_code, _) in Chain::get_chains().iter() {
            match generate_wallet_from_mnemonic(
                mnemonic.clone(),
                i32::from(chain_code),
                index,
                false,
            ) {
                Ok(account) => {
                    assert!(
                        !account.address.is_empty(),
                        "The address for chain {} is empty",
                        chain_code
                    );
                    assert!(
                        !account.private_key.is_empty(),
                        "The private_key for chain {} is empty",
                        chain_code
                    );
                    assert_eq!(
                        account.chain_id,
                        i32::from(chain_code),
                        "The chain_id doesn't match"
                    );
                }
                Err(e) => panic!("unexpected error! {}", e.to_string()),
            }
        }
    }

    #[test]
    fn should_get_account_from_private_key() {
        let private_key =
            "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d".to_string();
        let chain_id = 38;
        match generate_wallet_from_private_key(chain_id, private_key) {
            Ok(account) => {
                assert_eq!(
                    account.address,
                    "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy".to_string(),
                    "The address doesn't match"
                );
                assert_eq!(
                    account.private_key,
                    "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d".to_string(),
                    "The private_key doesn't match"
                );
                assert_eq!(account.chain_id, chain_id, "The chain_id doesn't match");
            }
            Err(_) => panic!("unexpected error!"),
        }
    }

    #[test]
    fn should_fail_to_get_account_from_private_key() {
        let private_key = "".to_string();
        let chain_id = 38;
        match generate_wallet_from_private_key(chain_id, private_key) {
            Ok(account) => panic!(
                "A error was expected but found a pk {}.",
                account.private_key
            ),
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), " Invalid error"),
        }
    }

    #[test]
    fn should_encrypt_with_gmc_and_decrypt_data() {
        let original_data = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let password = "myPass".to_string();
        let encrypted_data = encrypt_with_gmc(original_data.clone(), password.clone()).unwrap();
        let decrypted_data = decrypt(encrypted_data, password.clone()).unwrap();
        assert_eq!(original_data, decrypted_data, "The data is not the same");
    }

    #[test]
    fn should_encrypt_with_cbc_and_decrypt_data() {
        let original_data = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let password = "myPass".to_string();
        let encrypted_data = encrypt_with_cbc(original_data.clone(), password.clone()).unwrap();
        let decrypted_data = decrypt(encrypted_data, password.clone()).unwrap();
        assert_eq!(original_data, decrypted_data, "The data is not the same");
    }

    #[test]
    fn should_encrypt_with_cbf_and_decrypt_data() {
        let original_data = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let password = "myPass".to_string();
        let encrypted_data = encrypt_with_cfb(original_data.clone(), password.clone()).unwrap();
        let decrypted_data = decrypt(encrypted_data, password.clone()).unwrap();
        assert_eq!(original_data, decrypted_data, "The data is not the same");
    }

    #[test]
    fn should_fail_to_decrypt_with_wrong_password() {
        let original_data = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let password = "myPass".to_string();
        let encrypted_data = encrypt_with_gmc(original_data.clone(), password.clone()).unwrap();
        match decrypt(encrypted_data, "wrong".to_string()) {
            Ok(_) => panic!("A error was expected but found a decrypted data"),
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), " Invalid error"),
        }
    }
}
