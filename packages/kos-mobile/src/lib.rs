pub mod number;

use hex::FromHexError;
use hex::ToHex;
use kos::chains::util::hex_string_to_vec;
use kos::chains::{
    create_custom_evm, get_chain_by_base_id, Chain, ChainError, ChainOptions, Transaction,
};
use kos::crypto::cipher::CipherAlgo;
use kos::crypto::{base64, cipher};
use kos_codec::KosCodedAccount;
use kos_codec::{encode_for_broadcast, encode_for_signing};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KOSError {
    #[error("UnsupportedChainError: Unsupported chain {id}")]
    UnsupportedChain { id: String },
    #[error("KOSDelegateError: {0}")]
    KOSDelegate(String),
    #[error("HexDecodeError: {0}")]
    HexDecode(String),
    #[error("KOSNumberError: {0}")]
    KOSNumber(String),
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
    pub chain_id: u32,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub path: String,
}

#[derive(uniffi::Record)]
struct KOSTransaction {
    pub chain_id: u32,
    pub raw: String,
    pub sender: String,
    pub signature: String,
}

#[derive(uniffi::Enum)]
enum TransactionChainOptions {
    Evm {
        chain_id: u32,
    },
    Btc {
        prev_scripts: Vec<Vec<u8>>,
        input_amounts: Vec<u64>,
    },
    Substrate {
        call: Vec<u8>,
        era: Vec<u8>,
        nonce: u32,
        tip: u8,
        block_hash: Vec<u8>,
        genesis_hash: Vec<u8>,
        spec_version: u32,
        transaction_version: u32,
        app_id: Option<u32>,
    },
    Cosmos {
        chain_id: String,
        account_number: u64,
    },
}

#[allow(clippy::too_many_arguments)]
#[uniffi::export]
fn new_substrate_transaction_options(
    call: String,
    era: String,
    nonce: u32,
    tip: u8,
    block_hash: String,
    genesis_hash: String,
    spec_version: u32,
    transaction_version: u32,
    app_id: Option<u32>,
) -> TransactionChainOptions {
    let call = hex_string_to_vec(call.as_str()).unwrap_or_default();
    let era = hex_string_to_vec(era.as_str()).unwrap_or_default();
    let block_hash = hex_string_to_vec(block_hash.as_str()).unwrap_or_default();
    let genesis_hash = hex_string_to_vec(genesis_hash.as_str()).unwrap_or_default();

    TransactionChainOptions::Substrate {
        call,
        era,
        nonce,
        tip,
        block_hash,
        genesis_hash,
        spec_version,
        transaction_version,
        app_id,
    }
}

#[uniffi::export]
fn new_bitcoin_transaction_options(
    input_amounts: Vec<u64>,
    prev_scripts: Vec<String>,
) -> TransactionChainOptions {
    let prev_scripts = prev_scripts
        .iter()
        .map(|s| base64::simple_base64_decode(s).unwrap_or_default())
        .collect();

    TransactionChainOptions::Btc {
        prev_scripts,
        input_amounts,
    }
}

#[uniffi::export]
fn new_evm_transaction_options(chain_id: u32) -> TransactionChainOptions {
    TransactionChainOptions::Evm { chain_id }
}

#[uniffi::export]
fn new_cosmos_transaction_options(
    chain_id: String,
    account_number: u64,
) -> TransactionChainOptions {
    TransactionChainOptions::Cosmos {
        chain_id,
        account_number,
    }
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
    chain_id: u32,
    index: u32,
    use_legacy_path: bool,
) -> Result<KOSAccount, KOSError> {
    if !validate_mnemonic(mnemonic.clone()) {
        return Err(KOSError::KOSDelegate("Invalid mnemonic".to_string()));
    }
    let chain = get_chain_by(chain_id)?;
    let seed = chain.mnemonic_to_seed(mnemonic, String::from(""))?;
    let path = chain.get_path(index, use_legacy_path);
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
    chain_id: u32,
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

fn get_chain_by(id: u32) -> Result<Box<dyn Chain>, KOSError> {
    let chain = get_chain_by_base_id(id)
        .ok_or_else(|| KOSError::UnsupportedChain { id: id.to_string() })?;

    Ok(chain)
}

#[uniffi::export]
fn sign_transaction(
    account: KOSAccount,
    raw: String,
    options: Option<TransactionChainOptions>,
) -> Result<KOSTransaction, KOSError> {
    let options = match options {
        Some(TransactionChainOptions::Evm { chain_id }) => Some(ChainOptions::EVM { chain_id }),
        Some(TransactionChainOptions::Btc {
            prev_scripts,
            input_amounts,
        }) => Some(ChainOptions::BTC {
            prev_scripts,
            input_amounts,
        }),
        Some(TransactionChainOptions::Substrate {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        }) => Some(ChainOptions::SUBSTRATE {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        }),
        Some(TransactionChainOptions::Cosmos {
            chain_id,
            account_number,
        }) => Some(ChainOptions::COSMOS {
            chain_id,
            account_number,
        }),
        None => None,
    };

    let mut chain = get_chain_by(account.chain_id)?;

    if let Some(ChainOptions::EVM { chain_id }) = options {
        chain = create_custom_evm(chain_id).ok_or(KOSError::KOSDelegate(
            "Failed to create custom evm chain".to_string(),
        ))?;
    }

    let raw_tx_bytes = hex::decode(raw.clone())?;

    let transaction = Transaction {
        raw_data: raw_tx_bytes,
        signature: Vec::new(),
        tx_hash: Vec::new(),
        options,
    };

    let kos_codec_acc = KosCodedAccount {
        chain_id: account.chain_id,
        address: account.address.clone(),
        public_key: account.public_key.clone(),
    };

    let encoded = encode_for_signing(kos_codec_acc.clone(), transaction)?;

    let pk = hex::decode(account.private_key.clone())?;

    let signed_transaction = chain.sign_tx(pk, encoded)?;
    let signature = signed_transaction.signature.clone();

    let encoded_to_broadcast = encode_for_broadcast(kos_codec_acc, signed_transaction)?;

    Ok(KOSTransaction {
        chain_id: account.chain_id,
        raw: hex::encode(encoded_to_broadcast.raw_data),
        sender: account.address,
        signature: hex::encode(signature),
    })
}

#[uniffi::export]
fn sign_message(account: KOSAccount, hex: String) -> Result<Vec<u8>, KOSError> {
    let chain = get_chain_by(account.chain_id)?;
    let message = hex::decode(hex)?;
    let signature = chain.sign_message(hex::decode(account.private_key).unwrap(), message)?;
    Ok(signature)
}

#[uniffi::export]
fn is_chain_supported(chain_id: u32) -> bool {
    kos::chains::is_chain_supported(chain_id)
}

#[uniffi::export]
fn get_supported_chains() -> Vec<u32> {
    kos::chains::get_supported_chains()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use kos::chains::get_chains;

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
    fn should_fail_to_get_account_from_mnemonic_with_invalid_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon klv abandon abandon abandon abandon abandon about".to_string();
        let index = 0;
        let chain_id = 38;
        match generate_wallet_from_mnemonic(mnemonic, chain_id, index, false) {
            Ok(_) => panic!("A error was expected but found a account"),
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), " Invalid error"),
        }
    }

    #[test]
    fn should_get_all_supported_chains_account_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let index = 0;

        for chain_code in get_chains() {
            match generate_wallet_from_mnemonic(mnemonic.clone(), chain_code, index, false) {
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
                    assert_eq!(account.chain_id, chain_code, "The chain_id doesn't match");
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
            Err(e) => assert!(matches!(e, KOSError::KOSDelegate(..)), "Invalid error"),
        }
    }

    #[test]
    fn should_sign_raw_transaction() {
        let chain_id = 38;

        let raw = hex::encode("{\"RawData\":{\"BandwidthFee\":1000000,\"ChainID\":\"MTAwNDIw\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Version\":1}}".as_bytes());

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false,
        )
            .unwrap();

        let transaction = sign_transaction(account, raw.to_string(), None).unwrap();

        assert_eq!(transaction.chain_id, chain_id, "The chain_id doesn't match");
        assert_eq!(
            transaction.sender, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "The sender doesn't match"
        );
        assert_eq!(
            transaction.raw, "7b22426c6f636b223a6e756c6c2c2252617744617461223a7b2242616e647769647468466565223a313030303030302c22436861696e4944223a224d5441774e444977222c22436f6e7472616374223a5b7b22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6e7472616374222c2276616c7565223a224369417973796730416a38786a2f72723558475536694a2b41544932396d6e52485330573042724331767a304342674b227d2c2254797065223a6e756c6c7d5d2c2244617461223a6e756c6c2c224b417070466565223a3530303030302c224b4441466565223a6e756c6c2c224e6f6e6365223a33392c225065726d697373696f6e4944223a6e756c6c2c2253656e646572223a22354273794f6c6366325658676e4e5157595039455a6350305270504966792b75704b44385149636e794f6f3d222c2256657273696f6e223a317d2c225265636569707473223a6e756c6c2c22526573756c74223a6e756c6c2c22526573756c74436f6465223a6e756c6c2c225369676e6174757265223a5b2267555a444950537853713430516a54424d33382f4441417557546d37443154486f324b5756716869545943756d354f2b4f53577754596c6749553052674a36756e6767316375434a50636d59574e676a444b412f44413d3d225d7d",
            "The raw doesn't match"
        );
        assert_eq!(
            transaction.signature, "81464320f4b14aae344234c1337f3f0c002e5939bb0f54c7a3629656a8624d80ae9b93be3925b04d8960214d11809eae9e083572e0893dc99858d8230ca03f0c",
            "The signature doesn't match"
        );
    }

    #[test]
    fn should_sign_raw_transaction_cosmos() {
        let chain_id = 48;

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false,
        )
        .unwrap();

        let transaction = sign_transaction(
            account,
            "0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c06".to_string(),
            Some(TransactionChainOptions::Cosmos {
                chain_id: "celestia".to_string(),
                account_number: 274454,
            }),
        )
        .unwrap();

        assert_eq!(transaction.raw, "0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c061a409c611838f8614c3f9bbbda156d39f4219b8cbb181b0e34466d1e9daf05f5973c2f302f60d49333a0e12956021d51ce048b475765e6b46ba3c678594b1b7513f7", "The raw doesn't match");
    }

    #[test]
    fn should_sign_raw_transaction_bch() {
        let chain_id = 18;

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false,
        )
        .unwrap();

        let transaction = sign_transaction(
            account,
            "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000".to_string(),
            Some(TransactionChainOptions::Btc {
                prev_scripts: vec![
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                ],
                input_amounts: vec![498870, 1001016],
            }),
        )
        .unwrap();

        assert_eq!(transaction.raw, "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d010000006b48304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c010000006a4730440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000", "The raw doesn't match");
    }
    #[test]
    fn should_sign_raw_transaction_btc() {
        let chain_id = kos::chains::btc::ID;

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false,
        )
        .unwrap();

        let transaction = sign_transaction(
            account,
            "0100000002badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a00000000".to_string(),
            Some(TransactionChainOptions::Btc {
                prev_scripts: vec![
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                ],
                input_amounts: vec![5000, 10000],
            }),
        )
        .unwrap();

        assert_eq!(transaction.raw, "01000000000102badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a02483045022100ca1df8381e56e2ac2228e040cc2ff1c1079928222365f5c62cd6c18f398a6f55022029dca1177ab6edcfa03a25c7df32e1644c5d1fe496c6c7995a715373b56a591901210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c024830450221009496122a56551a0dab4fa8562474c943c79158f7592a845abd7b60ddf34c10c902205021b73e27a44b0c365fbd015133a4bb6dce79dd09705096de1c7b31a1f9b8a701210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c00000000", "The raw doesn't match");
    }

    #[test]
    fn should_sign_transaction_with_options() {
        let chain_id = 61;
        let raw =
            "b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080";

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false,
        )
            .unwrap();

        let options = new_evm_transaction_options(88888);
        let transaction = sign_transaction(account, raw.to_string(), Some(options)).unwrap();

        assert_eq!(transaction.raw, "02f87101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c001a044c69f41bf47ad50dc98c74af68811384c9172055b01fcaa39e70f53df69b632a05e071cf1f9e12500b525f03a29f567520e1ea49a97e6a29d1fd432dc6303353e", "The raw doesn't match");
    }

    #[test]
    fn should_sign_message() {
        let chain_id = 38;
        let message = hex::encode("Hello World".as_bytes());

        let account = generate_wallet_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain_id,
            0,
            false
        ).unwrap();

        let signature = sign_message(account, message).unwrap();
        assert_eq!(signature.len(), 64, "The signature length doesn't match");
    }

    #[test]
    fn should_return_true_for_supported_chain() {
        let chain_id = 38;
        let result = is_chain_supported(chain_id);
        assert!(result, "The chain should be supported");
    }

    #[test]
    fn should_return_false_for_unsupported_chain() {
        let chain_id = 999;
        let result = is_chain_supported(chain_id);
        assert!(!result, "The chain should not be supported");
    }

    #[test]
    fn should_get_supported_chains() {
        let supported_chains = get_supported_chains();
        assert!(
            !supported_chains.is_empty(),
            "The supported chains should not be empty"
        );
    }
}
