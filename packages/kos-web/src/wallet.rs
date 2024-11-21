use crate::models::{PathOptions, Transaction};

use pem::{parse as parse_pem, Pem};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};

use crate::utils::unpack;
use kos::chains::{get_chain_by_base_id, Transaction as KosTransaction};
use kos_types::error::Error;
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
    index: Option<u32>,
    encrypted_data: Option<Vec<u8>>,
    mnemonic: Option<String>,
    private_key: Option<String>,
    path: Option<String>,
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
        kos_crypto::mnemonic::validate_mnemonic(&mnemonic)?;

        let chain = get_chain_by_base_id(chain_id)
            .ok_or_else(|| Error::WalletManagerError("Invalid chain".to_string()))?;

        let seed = chain
            .mnemonic_to_seed(mnemonic.clone(), password.unwrap_or_default())
            .map_err(|e| Error::WalletManagerError(format!("mnemonic to seed: {}", e)))?;
        let private_key = chain
            .derive(seed, path.clone())
            .map_err(|e| Error::WalletManagerError(format!("derive keypair: {}", e)))?;

        let public_key = chain
            .get_pbk(private_key.clone())
            .map_err(|e| Error::WalletManagerError(format!("get public key: {}", e)))?;
        let address = chain
            .get_address(public_key)
            .map_err(|e| Error::WalletManagerError(format!("get address: {}", e)))?;

        Ok(Wallet {
            chain: chain_id,
            account_type: AccountType::Mnemonic,
            public_address: address,
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
            .ok_or_else(|| Error::WalletManagerError("Invalid chain".to_string()))?;
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
            return Err(Error::WalletManagerError("Invalid private key".to_string()));
        }

        let chain = get_chain_by_base_id(chain_id)
            .ok_or_else(|| Error::WalletManagerError("Invalid chain".to_string()))?;

        let public_key = chain
            .get_pbk(hex::decode(private_key_bytes.clone())?)
            .map_err(|e| Error::WalletManagerError(format!("get public key: {}", e)))?;
        let address = chain
            .get_address(public_key.clone())
            .map_err(|e| Error::WalletManagerError(format!("get address: {}", e)))?;

        // create wallet from keypair
        Ok(Wallet {
            chain: chain_id,
            account_type: AccountType::PrivateKey,
            public_address: address,
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
        let pem = parse_pem(data)
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        let content = String::from_utf8(pem.contents().to_vec())
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        let pk_hex = content.chars().take(64).collect::<String>();

        // import from private key
        Wallet::from_private_key(chain, pk_hex)
    }

    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(data: &[u8]) -> Result<Wallet, Error> {
        // parse pem
        let pem = parse_pem(data)
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        Wallet::import(pem)
    }
}

// wallet properties
impl Wallet {
    pub fn import(pem: Pem) -> Result<Wallet, Error> {
        // Deserialize decrypted bytes to WalletManager
        let wallet: Wallet = unpack(pem.contents())
            .map_err(|e| Error::CipherError(format!("deserialize data: {}", e)))?;

        Ok(wallet)
    }
}

#[wasm_bindgen]
// wallet properties
impl Wallet {
    // #[wasm_bindgen(js_name = "getChain")]
    // /// get wallet chain type
    // pub fn get_chain(&self) -> Chain {
    //     self.chain
    // }

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
        self.index.ok_or(Error::WalletManagerError(
            "Wallet is not created from mnemonic index".to_string(),
        ))
    }

    #[wasm_bindgen(js_name = "getPrivateKey")]
    /// get wallet private key
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
                    .ok_or_else(|| Error::WalletManagerError("Invalid chain".to_string()))?;

                chain
                    .sign_message(pk_bytes, message.to_vec())
                    .map_err(|e| Error::WalletManagerError(format!("sign message: {}", e)))
            }
            None => Err(Error::WalletManagerError("no keypair".to_string())),
        }
    }

    #[wasm_bindgen(js_name = "sign")]
    pub fn sign(&self, tx_raw: &[u8]) -> Result<Transaction, Error> {
        match self.private_key {
            Some(ref pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;

                let tx = KosTransaction {
                    raw_data: tx_raw.to_vec(),
                    signature: vec![],
                    tx_hash: vec![],
                };

                let chain = get_chain_by_base_id(self.chain)
                    .ok_or_else(|| Error::WalletManagerError("Invalid chain".to_string()))?;

                let signed_tx = chain
                    .sign_tx(pk_bytes, tx)
                    .map_err(|e| Error::WalletManagerError(format!("sign transaction: {}", e)))?;

                Ok(Transaction {
                    raw_data: signed_tx.raw_data,
                    tx_hash: signed_tx.tx_hash,
                    signature: signed_tx.signature,
                })
            }
            None => Err(Error::WalletManagerError("no keypair".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kos::chains::get_chain_by_base_id;

    #[test]
    fn test_export_import() {
        let default_password = "password";

        let chain = get_chain_by_base_id(38).unwrap();

        // create wallet
        let mut w1 = Wallet::from_mnemonic(
            38,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            chain.get_path(0, false),
            None,
        ).unwrap();

        // check if secret keys restored
        assert_eq!(
            w1.get_private_key(),
            "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d"
        );
        assert_eq!(w1.get_mnemonic(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert_eq!(w1.get_path(), "m/44'/690'/0'/0'/0'");
    }
}
