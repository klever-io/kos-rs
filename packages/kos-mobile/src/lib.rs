use hex::FromHexError;
use hex::ToHex;
use kos::chains::{get_chain_by_id, Chain, ChainError, Transaction};

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

impl From<ChainError> for KOSError {
    fn from(err: ChainError) -> Self {
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

#[derive(uniffi::Record)]
struct KOSTransaction {
    pub chain_id: i32,
    pub raw: String,
    pub sender: String,
    pub signature: String,
}

#[uniffi::export]
fn generate_mnemonic(size: i32) -> Result<String, KOSError> {
    Ok(kos::crypto::mnemonic::generate_mnemonic(size as usize)?.to_phrase())
}

#[uniffi::export]
fn validate_mnemonic(mnemonic: String) -> bool {
    kos::crypto::mnemonic::validate_mnemonic(mnemonic.as_str()).is_ok()
}

#[uniffi::export]
fn generate_wallet_from_mnemonic(
    mnemonic: String,
    chain_id: i32,
    index: i32,
    custom_path: Option<String>,
) -> Result<KOSAccount, KOSError> {
    if !validate_mnemonic(mnemonic.clone()) {
        return Err(KOSError::KOSDelegate("Invalid mnemonic".to_string()));
    }
    let chain = get_chain_by(chain_id)?;
    let seed = chain.mnemonic_to_seed(mnemonic, String::from(""))?;
    let path = chain.get_path(index as u32, custom_path);
    let private_key = chain.derive(seed, path.clone())?;

    let public_key = chain.get_pbk(private_key.clone())?;

    Ok(KOSAccount {
        chain_id,
        private_key: hex::encode(private_key),
        public_key: hex::encode(public_key.clone()),
        address: chain.get_address(public_key)?,
        path,
    })
}

#[uniffi::export]
fn generate_wallet_from_private_key(
    chain_id: i32,
    private_key: String,
) -> Result<KOSAccount, KOSError> {
    let chain = get_chain_by(chain_id)?;

    let public_key = chain.get_pbk(hex::decode(private_key.clone())?)?;
    let address = chain.get_address(public_key.clone())?;
    Ok(KOSAccount {
        chain_id,
        private_key: private_key.clone(),
        public_key: hex::encode(public_key.clone()),
        address,
        path: String::new(),
    })
}

#[uniffi::export]
fn encrypt_with_gmc(data: String, password: String) -> Result<String, KOSError> {
    todo!()
}

#[uniffi::export]
fn encrypt_with_cbc(data: String, password: String) -> Result<String, KOSError> {
    todo!()
}

#[uniffi::export]
fn encrypt_with_cfb(data: String, password: String) -> Result<String, KOSError> {
    todo!()
}

#[uniffi::export]
fn decrypt(data: String, password: String) -> Result<String, KOSError> {
    todo!()
}

fn get_chain_by(id: i32) -> Result<Box<dyn Chain>, KOSError> {
    let id_u8 = u32::try_from(id).map_err(|_| KOSError::UnsupportedChain { id: id.to_string() })?;
    let chain =
        get_chain_by_id(id_u8).ok_or_else(|| KOSError::UnsupportedChain { id: id.to_string() })?;

    Ok(chain)
}

#[uniffi::export]
fn sign_transaction(account: KOSAccount, raw: String) -> Result<KOSTransaction, KOSError> {
    let chain = get_chain_by(account.chain_id)?;
    let raw_tx_bytes = hex::decode(raw.clone())?;
    let transaction = Transaction {
        raw_data: raw_tx_bytes,
        signature: Vec::new(),
        tx_hash: Vec::new(),
    };
    let pk = hex::decode(account.private_key.clone())?;

    let signed_transaction = chain.sign_tx(pk, transaction)?;
    let signature = signed_transaction.signature;

    Ok(KOSTransaction {
        chain_id: account.chain_id,
        raw: hex::encode(signed_transaction.raw_data),
        sender: account.address,
        signature: hex::encode(signature),
    })
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
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, None) {
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
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, None) {
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
    fn should_fail_to_get_account_from_mnemonic_with_invalid_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon klv abandon abandon abandon abandon abandon about".to_string();
        let index = 0;
        let chain_id = 38;
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, None) {
            Ok(_) => panic!("A error was expected but found a account"),
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), " Invalid error"),
        }
    }

    #[test]
    // fn should_get_all_supported_chains_account_from_mnemonic() {
    //     let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
    //     let index = 0;
    //     for (&chain_code, _) in Chain::get_chains().iter() {
    //         println!("code = {}", chain_code)
    //     }
    //     for (&chain_code, _) in Chain::get_chains().iter() {
    //         match generate_wallet_from_mnemonic(
    //             mnemonic.clone(),
    //             i32::from(chain_code),
    //             index,
    //             false,
    //         ) {
    //             Ok(account) => {
    //                 assert!(
    //                     !account.address.is_empty(),
    //                     "The address for chain {} is empty",
    //                     chain_code
    //                 );
    //                 assert!(
    //                     !account.private_key.is_empty(),
    //                     "The private_key for chain {} is empty",
    //                     chain_code
    //                 );
    //                 assert_eq!(
    //                     account.chain_id,
    //                     i32::from(chain_code),
    //                     "The chain_id doesn't match"
    //                 );
    //             }
    //             Err(e) => panic!("unexpected error! {}", e.to_string()),
    //         }
    //     }
    // }
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
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), "Invalid error"),
        }
    }

    #[test]
    fn should_sign_raw_transaction() {
        let chain_id = 38;

        let raw = hex::encode("{\"RawData\":{\"BandwidthFee\":1000000,\"ChainID\":\"MTAwNDIw\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Version\":1}}".as_bytes());

        let account = generate_wallet_from_mnemonic(
            "permit best kiwi blast purchase cook grab present have hurdle quarter steak"
                .to_string(),
            chain_id,
            0,
            None,
        )
        .unwrap();

        let transaction = sign_transaction(account, raw.to_string()).unwrap();

        assert_eq!(transaction.chain_id, chain_id, "The chain_id doesn't match");
        assert_eq!(
            transaction.sender, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "The sender doesn't match"
        );
        assert_eq!(
            transaction.raw, "{\"RawData\":{\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Contract\":[{\"Parameter\":{\"typeUrl\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"BandwidthFee\":1000000,\"Version\":1,\"ChainID\":\"MTAwNDIw\"},\"Signature\":[\"gUZDIPSxSq40QjTBM38/DAAuWTm7D1THo2KWVqhiTYCum5O+OSWwTYlgIU0RgJ6ungg1cuCJPcmYWNgjDKA/DA==\"]}",
            "The raw doesn't match"
        );
        assert_eq!(
            transaction.signature, "gUZDIPSxSq40QjTBM38/DAAuWTm7D1THo2KWVqhiTYCum5O+OSWwTYlgIU0RgJ6ungg1cuCJPcmYWNgjDKA/DA==",
            "The signature doesn't match"
        );
    }
}
