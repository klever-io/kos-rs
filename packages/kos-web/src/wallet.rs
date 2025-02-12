use crate::models::{PathOptions, Transaction};

use pem::{parse as parse_pem, Pem};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};

use crate::error::Error;
use crate::utils::unpack;
use kos::chains::util::hex_string_to_vec;
use kos::chains::{get_chain_by_base_id, ChainOptions, Transaction as KosTransaction};
use kos::crypto::base64;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, EnumCount, IntoStaticStr)]
pub enum AccountType {
    Mnemonic,
    PrivateKey,
    KleverSafe,
    ReadOnly,
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Wallet {
    chain: u32,
    account_type: AccountType,
    public_address: String,
    public_key: String,
    index: Option<u32>,
    encrypted_data: Option<Vec<u8>>,
    mnemonic: Option<String>,
    private_key: Option<String>,
    path: Option<String>,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct TransactionChainOptions {
    #[wasm_bindgen(skip)]
    pub data: ChainOptions,
}

#[wasm_bindgen]
impl TransactionChainOptions {
    #[wasm_bindgen(js_name = "newBitcoinSignOptions")]
    pub fn new_bitcoin_sign_options(
        input_amounts: Vec<u64>,
        prev_scripts: Vec<String>,
    ) -> TransactionChainOptions {
        let prev_scripts = prev_scripts
            .iter()
            .map(|s| base64::simple_base64_decode(s).unwrap_or_default())
            .collect();

        TransactionChainOptions {
            data: ChainOptions::BTC {
                prev_scripts,
                input_amounts,
            },
        }
    }

    #[wasm_bindgen(js_name = "newEthereumSignOptions")]
    pub fn new_ethereum_sign_options(chain_id: u32) -> TransactionChainOptions {
        TransactionChainOptions {
            data: ChainOptions::EVM { chain_id },
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = "newSubstrateSignOptions")]
    pub fn new_substrate_sign_options(
        call: String,
        era: String,
        nonce: u32,
        tip: u8,
        block_hash: String,
        genesis_hash: String,
        spec_version: u32,
        transaction_version: u32,
        app_id: Option<u32>,
    ) -> Result<TransactionChainOptions, Error> {
        let call = hex_string_to_vec(call.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid call hex: {}", e)))?;
        let era = hex_string_to_vec(era.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid era hex: {}", e)))?;
        let block_hash = hex_string_to_vec(block_hash.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid block hash hex: {}", e)))?;
        let genesis_hash = hex_string_to_vec(genesis_hash.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid genesis hash hex: {}", e)))?;

        Ok(TransactionChainOptions {
            data: ChainOptions::SUBSTRATE {
                call,
                era,
                nonce,
                tip,
                block_hash,
                genesis_hash,
                spec_version,
                transaction_version,
                app_id,
            },
        })
    }
}

#[wasm_bindgen]
impl Wallet {
    #[wasm_bindgen(js_name = "fromMnemonic")]
    /// restore wallet from mnemonic
    pub fn from_mnemonic(
        chain_id: u32,
        mnemonic: String,
        path: String,
        password: Option<String>,
    ) -> Result<Wallet, Error> {
        // validate mnemonic entropy
        kos::crypto::mnemonic::validate_mnemonic(&mnemonic)?;

        let chain = get_chain_by_base_id(chain_id)
            .ok_or_else(|| Error::WalletManager("Invalid chain".to_string()))?;

        let seed = chain
            .mnemonic_to_seed(mnemonic.clone(), password.unwrap_or_default())
            .map_err(|e| Error::WalletManager(format!("mnemonic to seed: {}", e)))?;
        let private_key = chain
            .derive(seed, path.clone())
            .map_err(|e| Error::WalletManager(format!("derive keypair: {}", e)))?;

        let public_key = chain
            .get_pbk(private_key.clone())
            .map_err(|e| Error::WalletManager(format!("get public key: {}", e)))?;
        let address = chain
            .get_address(public_key.clone())
            .map_err(|e| Error::WalletManager(format!("get address: {}", e)))?;

        Ok(Wallet {
            chain: chain_id,
            account_type: AccountType::Mnemonic,
            public_address: address,
            public_key: hex::encode(public_key),
            index: None,
            encrypted_data: None,
            private_key: Some(hex::encode(private_key)),
            mnemonic: Some(mnemonic),
            path: Some(path),
        })
    }

    #[wasm_bindgen(js_name = "fromMnemonicIndex")]
    /// restore wallet from mnemonic
    pub fn from_mnemonic_index(
        chain_id: u32,
        mnemonic: String,
        path_options: &PathOptions,
        password: Option<String>,
    ) -> Result<Wallet, Error> {
        let chain = get_chain_by_base_id(chain_id)
            .ok_or_else(|| Error::WalletManager("Invalid chain".to_string()))?;
        let path = chain.get_path(path_options.index, path_options.is_legacy.unwrap());

        let mut wallet = Wallet::from_mnemonic(chain_id, mnemonic, path, password)?;
        wallet.index = Some(path_options.index);

        Ok(wallet)
    }

    #[wasm_bindgen(js_name = "fromPrivateKey")]
    /// restore wallet from mnemonic
    pub fn from_private_key(chain_id: u32, private_key: String) -> Result<Wallet, Error> {
        // convert hex to bytes
        let private_key_bytes = hex::decode(private_key.clone())?;

        // check size of private key
        if private_key_bytes.len() != 32 {
            return Err(Error::WalletManager("Invalid private key".to_string()));
        }

        let chain = get_chain_by_base_id(chain_id)
            .ok_or_else(|| Error::WalletManager("Invalid chain".to_string()))?;

        let public_key = chain
            .get_pbk(private_key_bytes.clone())
            .map_err(|e| Error::WalletManager(format!("get public key: {}", e)))?;
        let address = chain
            .get_address(public_key.clone())
            .map_err(|e| Error::WalletManager(format!("get address: {}", e)))?;

        // create wallet from keypair
        Ok(Wallet {
            chain: chain_id,
            account_type: AccountType::PrivateKey,
            public_address: address,
            public_key: hex::encode(public_key),
            index: None,
            encrypted_data: None,
            mnemonic: None,
            private_key: Some(private_key),
            path: None,
        })
    }

    #[wasm_bindgen(js_name = "fromKCPem")]
    /// restore wallet from mnemonic
    pub fn from_kc_pem(chain: u32, data: &[u8]) -> Result<Wallet, Error> {
        // decode pem file
        let pem =
            parse_pem(data).map_err(|_| Error::WalletManager("Invalid PEM data".to_string()))?;

        let content = String::from_utf8(pem.contents().to_vec())
            .map_err(|_| Error::WalletManager("Invalid PEM data".to_string()))?;

        let pk_hex = content.chars().take(64).collect::<String>();

        // import from private key
        Wallet::from_private_key(chain, pk_hex)
    }

    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(data: &[u8]) -> Result<Wallet, Error> {
        // parse pem
        let pem =
            parse_pem(data).map_err(|_| Error::WalletManager("Invalid PEM data".to_string()))?;

        Wallet::import(pem)
    }
}

// wallet properties
impl Wallet {
    pub fn import(pem: Pem) -> Result<Wallet, Error> {
        // Deserialize decrypted bytes to WalletManager
        let wallet: Wallet = unpack(pem.contents())
            .map_err(|e| Error::Cipher(format!("deserialize data: {}", e)))?;

        Ok(wallet)
    }
}

#[wasm_bindgen]
// wallet properties
impl Wallet {
    #[wasm_bindgen(js_name = "getChain")]
    // /// get wallet chain type
    pub fn get_chain(&self) -> u32 {
        self.chain
    }

    #[wasm_bindgen(js_name = "getAccountType")]
    /// get wallet account type
    pub fn get_account_type(&self) -> AccountType {
        self.account_type
    }

    #[wasm_bindgen(js_name = "getAddress")]
    /// get wallet address
    pub fn get_address(&self) -> String {
        self.public_address.clone()
    }

    #[wasm_bindgen(js_name = "getPublicKey")]
    /// get wallet public key
    /// returns hex encoded public key
    pub fn get_public_key(&self) -> String {
        self.public_key.clone()
    }
    #[wasm_bindgen(js_name = "getPath")]
    /// get wallet path if wallet is created from mnemonic
    pub fn get_path(&self) -> String {
        match self.path {
            Some(ref path) => path.clone(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "getIndex")]
    /// get wallet index if wallet is created from mnemonic index
    pub fn get_index(&self) -> Result<u32, Error> {
        self.index.ok_or(Error::WalletManager(
            "Wallet is not created from mnemonic index".to_string(),
        ))
    }

    #[wasm_bindgen(js_name = "getPrivateKey")]
    /// get wallet private key
    /// returns hex encoded private key
    pub fn get_private_key(&self) -> String {
        match self.private_key {
            Some(ref pk) => pk.clone(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "getMnemonic")]
    /// get wallet mnemonic if wallet is created from mnemonic
    pub fn get_mnemonic(&self) -> String {
        match self.mnemonic {
            Some(ref mnemonic) => mnemonic.clone(),
            None => String::new(),
        }
    }
}

#[wasm_bindgen]
// wallet methods
impl Wallet {
    #[wasm_bindgen(js_name = "signMessage")]
    /// sign message with keypair
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match self.private_key {
            Some(ref pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;
                let chain = get_chain_by_base_id(self.chain)
                    .ok_or_else(|| Error::WalletManager("Invalid chain".to_string()))?;

                chain
                    .sign_message(pk_bytes, message.to_vec())
                    .map_err(|e| Error::WalletManager(format!("sign message: {}", e)))
            }
            None => Err(Error::WalletManager("no keypair".to_string())),
        }
    }

    #[wasm_bindgen(js_name = "sign")]
    /// sign transaction with keypair
    pub fn sign(
        &self,
        tx_raw: &[u8],
        options: Option<TransactionChainOptions>,
    ) -> Result<Transaction, Error> {
        match self.private_key {
            Some(ref pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;

                let options = options.map(|o| o.data);

                let tx = KosTransaction {
                    raw_data: tx_raw.to_vec(),
                    signature: vec![],
                    tx_hash: vec![],
                    options,
                };

                let chain = get_chain_by_base_id(self.chain)
                    .ok_or_else(|| Error::WalletManager("Invalid chain".to_string()))?;

                let signed_tx = chain
                    .sign_tx(pk_bytes, tx)
                    .map_err(|e| Error::WalletManager(format!("sign transaction: {}", e)))?;

                Ok(Transaction {
                    raw_data: signed_tx.raw_data,
                    tx_hash: signed_tx.tx_hash,
                    signature: signed_tx.signature,
                })
            }
            None => Err(Error::WalletManager("no private key".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kos::chains::get_chain_by_base_id;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_PRIVATE_KEY: &str =
        "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d";
    const TEST_PUBLIC_KEY: &str =
        "e41b323a571fd955e09cd41660ff4465c3f44693c87f2faea4a0fc408727c8ea";

    #[test]
    fn test_wallet_from_mnemonic() {
        let chain_id = 38;
        let chain = get_chain_by_base_id(chain_id).unwrap();
        let path = chain.get_path(0, false);

        let wallet =
            Wallet::from_mnemonic(chain_id, TEST_MNEMONIC.to_string(), path.clone(), None).unwrap();

        assert_eq!(wallet.get_chain(), chain_id);
        assert_eq!(wallet.get_account_type(), AccountType::Mnemonic);
        assert_eq!(wallet.get_private_key(), TEST_PRIVATE_KEY);
        assert_eq!(
            wallet.get_public_key(),
            "e41b323a571fd955e09cd41660ff4465c3f44693c87f2faea4a0fc408727c8ea"
        );
        assert_eq!(wallet.get_path(), path);
        assert_eq!(wallet.get_mnemonic(), TEST_MNEMONIC);
    }

    #[test]
    fn test_wallet_from_mnemonic_with_password() {
        let chain_id = 38;
        let chain = get_chain_by_base_id(chain_id).unwrap();
        let path = chain.get_path(0, false);
        let password = Some("mysecretpassword".to_string());

        let wallet =
            Wallet::from_mnemonic(chain_id, TEST_MNEMONIC.to_string(), path, password).unwrap();

        assert_eq!(wallet.get_account_type(), AccountType::Mnemonic);
        assert_eq!(wallet.get_private_key().len(), 64); // Should be valid hex
    }

    #[test]
    fn test_wallet_from_mnemonic_index() {
        let chain_id = 38;
        let index = 5;

        let path_options = PathOptions {
            index,
            is_legacy: Some(false),
        };

        let wallet =
            Wallet::from_mnemonic_index(chain_id, TEST_MNEMONIC.to_string(), &path_options, None)
                .unwrap();

        assert_eq!(wallet.get_index().unwrap(), index);
        assert_eq!(wallet.get_account_type(), AccountType::Mnemonic);
        assert_eq!(
            wallet.get_private_key(),
            "384f7222481134ed0b48416f986bc6c3660867340ef80fadd72db3388feafa8d"
        );
        assert_eq!(
            wallet.get_public_key(),
            "b94cd4566b6e6f18128e833b5d8ce50d5f11c0b816223f0210b552fa5c04979c"
        );
        assert!(wallet.get_path().contains(&index.to_string()));
    }

    #[test]
    fn test_wallet_from_private_key() {
        let chain_id = 38;

        let wallet = Wallet::from_private_key(chain_id, TEST_PRIVATE_KEY.to_string()).unwrap();

        assert_eq!(wallet.get_chain(), chain_id);
        assert_eq!(wallet.get_account_type(), AccountType::PrivateKey);
        assert_eq!(wallet.get_private_key(), TEST_PRIVATE_KEY);
        assert_eq!(wallet.get_public_key(), TEST_PUBLIC_KEY);
        assert!(wallet.get_mnemonic().is_empty());
        assert!(wallet.get_path().is_empty());
    }

    #[test]
    fn test_invalid_private_key() {
        let chain_id = 38;
        let invalid_pk = "invalid_private_key";

        let result = Wallet::from_private_key(chain_id, invalid_pk.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_message() {
        let chain_id = 38;
        let message = b"Hello, World!";

        let wallet = Wallet::from_private_key(chain_id, TEST_PRIVATE_KEY.to_string()).unwrap();

        let signature = wallet.sign_message(message).unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_multiple_chains() {
        let test_chains = vec![2, 38, 60];

        for chain_id in test_chains {
            let chain = get_chain_by_base_id(chain_id).unwrap();
            let path = chain.get_path(0, false);

            let wallet =
                Wallet::from_mnemonic(chain_id, TEST_MNEMONIC.to_string(), path, None).unwrap();

            assert_eq!(wallet.get_chain(), chain_id);
            assert!(!wallet.get_address().is_empty());
        }
    }

    #[test]
    fn test_invalid_chain() {
        let invalid_chain_id = 9999;
        let chain = get_chain_by_base_id(2).unwrap();
        let path = chain.get_path(0, false);

        let result = Wallet::from_mnemonic(invalid_chain_id, TEST_MNEMONIC.to_string(), path, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let chain_id = 38;
        let invalid_mnemonic = "invalid mnemonic phrase";
        let chain = get_chain_by_base_id(chain_id).unwrap();
        let path = chain.get_path(0, false);

        let result = Wallet::from_mnemonic(chain_id, invalid_mnemonic.to_string(), path, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_readonly_wallet_operations() {
        let chain_id = 38;
        let public_address = "klv1fpwjz6w9sutqhfd4yf36zmd894de3h4ECt3";

        let wallet = Wallet {
            chain: chain_id,
            account_type: AccountType::ReadOnly,
            public_address: public_address.to_string(),
            public_key: TEST_PUBLIC_KEY.to_string(),
            index: None,
            encrypted_data: None,
            mnemonic: None,
            private_key: None,
            path: None,
        };

        assert_eq!(wallet.get_address(), public_address);
        assert!(wallet.get_private_key().is_empty());
        assert!(wallet.get_mnemonic().is_empty());

        // Signing operations should fail
        let message = b"test message";
        assert!(wallet.sign_message(message).is_err());
    }

    #[test]
    fn test_sign_transaction() {
        let chain_id = 38;
        let chain = get_chain_by_base_id(chain_id).unwrap();
        let path = chain.get_path(0, false);

        let wallet =
            Wallet::from_mnemonic(chain_id, TEST_MNEMONIC.to_string(), path, None).unwrap();

        let tx_raw = r#"{"RawData":{"Sender":"UMjR49Dkn+HleedQY88TSjXXJhtbDpX7f7QVF/Dcqos=","Contract":[{"Type":63,"Parameter":{"type_url":"type.googleapis.com/proto.SmartContract","value":"EiAAAAAAAAAAAAUAIPnuq04LIuz1ew83LbqEVgLiyNyybBoRCghGUkctMlZCVRIFCIDh6xc="}}],"Data":["c3Rha2VGYXJt"],"KAppFee":2000000,"BandwidthFee":4622449,"Version":1,"ChainID":"MTAwMDAx"}}"#;

        let signed_tx = wallet.sign(tx_raw.as_bytes(), None).unwrap();

        assert!(!signed_tx.signature.is_empty());
        assert!(!signed_tx.tx_hash.is_empty());
    }
}
