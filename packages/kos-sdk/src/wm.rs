use crate::{wallet::Wallet, models::PathOptions};
use kos_types::error::Error;
use kos_utils::{pack, unpack};

use pem::{
    encode as encode_pem, encode_many as encode_many_pem, parse as parse_pem,
    parse_many as parse_many_pem, Pem,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

const KOS_WM_TAG: &str = "KOS WALLET MANAGER";
const KOS_WM_TAG_DEFAULT: &str = "KOS WM DEFAULT";

#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalletManager {
    is_locked: bool,
    encrypted_data: Option<Vec<u8>>,
    checksum: Option<Vec<u8>>,
    // skip serializing wallets, all data must be encrypted into encrypted_data
    #[serde(skip)]
    wallets: HashMap<String, Wallet>,
}

#[wasm_bindgen]
impl WalletManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WalletManager {
        WalletManager {
            is_locked: false,
            encrypted_data: None,
            checksum: None,
            wallets: HashMap::new(),
        }
    }

    #[wasm_bindgen(js_name = "verifyPassword")]
    pub fn verify_password(&self, password: String) -> Result<(), Error> {
        _ = self
            .encrypted_data
            .as_ref()
            .ok_or_else(|| Error::WalletManagerError("No encrypted data".to_string()))?;
        let checksum = self
            .checksum
            .as_ref()
            .ok_or_else(|| Error::WalletManagerError("No checksum".to_string()))?;

        let checksum_str = String::from_utf8(checksum.clone())
            .map_err(|_| Error::WalletManagerError("Invalid checksum".to_string()))?;

        if !kos_crypto::cipher::check_checksum(&password, checksum_str) {
            return Err(Error::WalletManagerError("Invalid password".to_string()));
        }

        Ok(())
    }

    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(data: &[u8]) -> Result<WalletManager, Error> {
        // parse pem
        let pem = parse_pem(data)
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        WalletManager::import(pem)
    }

    #[wasm_bindgen(js_name = "toPem")]
    pub fn to_pem(&self, password: String) -> Result<Vec<u8>, Error> {
        let pem = self.export(password)?;

        Ok(encode_pem(&pem).as_bytes().to_vec())
    }

    #[wasm_bindgen(js_name = "isLocked")]
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    #[wasm_bindgen(js_name = "unlock")]
    pub fn unlock(&mut self, password: String) -> Result<(), Error> {
        // return if already unlocked
        if !self.is_locked() {
            return Ok(());
        }

        // verify password
        self.verify_password(password.clone())?;

        // reload encrypted wallets from encrypted_data
        let wallets = parse_many_pem(self.encrypted_data.as_ref().unwrap())
            .map_err(|_| Error::WalletManagerError("Invalid encrypted data".to_string()))?;

        // deserialize all wallets and save to encrypted_data
        for pem in wallets.iter() {
            let wallet = Wallet::import(pem.clone())?;
            self.wallets
                .insert(pem.tag().to_string(), wallet.to_owned());
        }

        // unlock status
        self.is_locked = false;

        Ok(())
    }

    #[wasm_bindgen(js_name = "lock")]
    pub fn lock(&mut self, password: String) -> Result<(), Error> {
        // return if is locked
        if self.is_locked() {
            return Ok(());
        }

        // verify password if encrypted data is present
        if self.encrypted_data.is_some() {
            self.verify_password(password.clone())?;
        }

        let wallets: Result<Vec<Pem>, Error> = self
            .wallets
            .iter_mut()
            .map(|(tag, wallet)| {
                wallet.lock(password.clone())?;
                let w = wallet.export(password.clone())?;

                // replace default tag with KOS_WM_TAG_DEFAULT
                Ok(if tag == KOS_WM_TAG_DEFAULT {
                    Pem::new(KOS_WM_TAG_DEFAULT, w.contents())
                } else {
                    w
                })
            })
            .collect();

        let wallets = wallets?;

        self.encrypted_data = Some(encode_many_pem(&wallets).as_bytes().to_vec());
        self.checksum = Some(
            kos_crypto::cipher::create_checksum(&password)
                .as_bytes()
                .to_vec(),
        );

        // reset secrets
        self.wallets.clear();
        self.is_locked = true;

        Ok(())
    }
}

impl WalletManager {
    pub fn import(pem: Pem) -> Result<WalletManager, Error> {
        // check tag
        if pem.tag() != KOS_WM_TAG {
            return Err(Error::WalletManagerError("Invalid PEM tag".to_string()));
        }

        // Deserialize decrypted bytes to WalletManager
        let wm: WalletManager = unpack(pem.contents())
            .map_err(|e| Error::CipherError(format!("deserialize wm: {}", e)))?;

        Ok(wm)
    }

    pub fn export(&self, password: String) -> Result<Pem, Error> {
        // validate password and lock wallet
        if !self.is_locked() {
            return Err(Error::WalletManagerError(
                "WalletManager is not locked".to_string(),
            ));
        }

        self.verify_password(password.clone())?;

        let data = pack(self).map_err(|e| Error::CipherError(format!("serialize wm: {}", e)))?;

        let pem = kos_crypto::cipher::to_pem(KOS_WM_TAG.to_owned(), &data)?;

        Ok(pem)
    }
}

impl Default for WalletManager {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WalletManager {
    fn ensure_unlocked(&mut self, password: String) -> Result<(), Error> {
        if !self.is_locked() {
            self.unlock(password)
        } else {
            self.verify_password(password)
        }
    }

    #[wasm_bindgen(js_name = "addWallet")]
    pub fn add_wallet(&mut self, wallet: Wallet, password: String) -> Result<Wallet, Error> {
        self.ensure_unlocked(password.clone())?;

        let mut wallet = wallet.clone();

        // check if wallet is locked
        if !wallet.is_locked() {
            wallet.lock(password.clone())?;
        } else {
            wallet.verify_password(password.clone())?;
        }

        let wallet_name = wallet.get_key();

        // error if exists
        if self.wallets.contains_key(&wallet_name) {
            return Err(Error::WalletManagerError(
                "Wallet already exists".to_string(),
            ));
        }

        self.wallets.insert(wallet_name, wallet.clone());

        Ok(wallet)
    }

    #[wasm_bindgen(js_name = "newWallet")]
    pub fn new_wallet(
        &mut self,
        chain: crate::chain::Chain,
        password: String,
    ) -> Result<Wallet, Error> {
        self.ensure_unlocked(password.clone())?;

        let index = self
            .wallets
            .values()
            .filter(|wallet| {
                wallet.get_chain() == chain
                    && wallet.get_account_type() == crate::wallet::AccountType::Mnemonic
            })
            .filter_map(|wallet| wallet.get_index().ok())
            .max()
            .map(|x| x + 1)
            .unwrap_or(0);

        let mut wallet = Wallet::from_mnemonic_index(
            chain,
            self.get_mnemonic(password.to_owned())?,
            &PathOptions::new(index),
            None,
        )?;

        wallet.lock(password.clone())?;

        self.add_wallet(wallet, password)
    }

    #[wasm_bindgen(js_name = "removeWallet")]
    pub fn remove_wallet(
        &mut self,
        chain: crate::chain::Chain,
        address: String,
    ) -> Result<(), Error> {
        let wallet_name = Wallet::wallet_key(chain, &address);
        match self.wallets.remove(&wallet_name) {
            Some(_) => Ok(()),
            None => Err(Error::WalletManagerError(format!(
                "Wallet with address {} not found",
                address
            ))),
        }
    }

    #[wasm_bindgen(js_name = "getWallet")]
    pub fn get_wallet(&self, chain: crate::chain::Chain, address: String) -> Result<Wallet, Error> {
        let wallet_name = Wallet::wallet_key(chain, &address);
        match self.wallets.get(&wallet_name) {
            Some(wallet) => Ok(wallet.clone()),
            None => Err(Error::WalletManagerError(format!(
                "Wallet with address {} not found",
                address
            ))),
        }
    }

    #[wasm_bindgen(js_name = "getMnemonic")]
    pub fn get_mnemonic(&self, password: String) -> Result<String, Error> {
        // error if unlocked
        if self.is_locked() {
            return Err(Error::WalletManagerError(
                "WalletManager is locked".to_string(),
            ));
        }

        // reload encrypted wallets from encrypted_data
        let mut w_mnemonic = self
            .wallets
            .get(KOS_WM_TAG_DEFAULT)
            .ok_or(Error::WalletManagerError(
                "Default mnemonic not found".to_string(),
            ))?
            .to_owned();

        // decrypt mnemonic
        w_mnemonic.unlock(password.clone())?;
        let mnemonic_str = w_mnemonic.get_mnemonic();
        if mnemonic_str.is_empty() {
            return Err(Error::WalletManagerError(
                "Default mnemonic not found".to_string(),
            ));
        }

        Ok(mnemonic_str)
    }

    #[wasm_bindgen(js_name = "setMnemonic")]
    pub fn set_mnemonic(&mut self, mnemonic: String, password: String) -> Result<(), Error> {
        // error if unlocked
        if self.is_locked() {
            return Err(Error::WalletManagerError(
                "WalletManager is locked".to_string(),
            ));
        }

        // error if default mnemonic exists
        if self.wallets.contains_key(KOS_WM_TAG_DEFAULT) {
            return Err(Error::WalletManagerError(
                "Default mnemonic already exists".to_string(),
            ));
        }

        // create wallet
        let mut wallet = Wallet::from_mnemonic(
            crate::chain::Chain::NONE,
            mnemonic.clone(),
            "".to_string(),
            None,
        )?;

        wallet.lock(password.clone())?;
        self.wallets.insert(KOS_WM_TAG_DEFAULT.to_owned(), wallet);

        Ok(())
    }

    #[wasm_bindgen(js_name = "viewWallets")]
    pub fn view_wallets(&self) -> Result<JsValue, Error> {
        let wallets = self.list_wallets();
        serde_wasm_bindgen::to_value(&wallets).map_err(|e| Error::JSONSerde(e.to_string()))
    }
}

impl WalletManager {
    pub fn list_wallets(&self) -> Vec<WalletView> {
        let mut wallets = Vec::new();
        for w in self.wallets.values() {
            // skip default mnemonic wallet
            if w.get_chain() == crate::chain::Chain::NONE {
                continue;
            }

            wallets.push(WalletView {
                chain: w.get_chain(),
                address: w.get_address(),
                // todo!("add name to wallet struct")
                name: w.get_key(),
            });
        }
        wallets
    }
}

#[derive(Deserialize, Serialize)]
pub struct WalletView {
    pub chain: crate::chain::Chain,
    pub address: String,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    const DEFAULT_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_wallet_manager_export_import() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();
        let wallet = Wallet::new(Chain::KLV).unwrap();
        let result = wm.add_wallet(wallet.to_owned(), default_password.to_owned());
        assert!(result.is_ok());

        // set default mnemonic
        wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password.to_string())
            .unwrap();

        let result = wm.export(default_password.to_owned());
        assert_eq!(
            result.err(),
            Some(Error::WalletManagerError(
                "WalletManager is not locked".to_string()
            ))
        );

        let result = wm.lock(default_password.to_owned());
        assert!(result.is_ok());
        let pem = wm.export(default_password.to_owned());
        assert!(pem.is_ok());

        let mut wm2 = WalletManager::import(pem.unwrap()).unwrap();
        // unlock wallet manager
        let result = wm2.unlock(default_password.to_owned());
        assert!(result.is_ok());
        // count should be 2 dues to default mnemonic wallet
        assert_eq!(wm2.wallets.len(), 2);

        // check if wallet address matches
        let wallet2 = wm2
            .get_wallet(wallet.get_chain(), wallet.get_address())
            .unwrap();
        assert_eq!(wallet2.get_address(), wallet.get_address());

        // check default mnemonic matchs
        let mnemonic = wm2.get_mnemonic(default_password.to_owned()).unwrap();
        assert_eq!(mnemonic, DEFAULT_MNEMONIC);
    }

    #[test]
    fn test_wallet_manager_lock_unlock() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();
        let wallet = Wallet::new(Chain::KLV).unwrap();
        let test_privete_key = wallet.get_private_key();

        let resul = wm.add_wallet(wallet.clone(), default_password.to_owned());
        assert!(resul.is_ok());
        let result = wm.lock(default_password.to_owned());
        assert!(result.is_ok());
        assert!(wm.is_locked());
        assert_eq!(wm.wallets.len(), 0);
        // try unlock with wrong password
        let result = wm.unlock("wrong_password".to_owned());
        assert_eq!(
            result.err(),
            Some(Error::WalletManagerError("Invalid password".to_string()))
        );
        // unlock with correct password
        let result = wm.unlock(default_password.to_owned());
        assert!(result.is_ok());
        assert!(!wm.is_locked());
        assert_eq!(wm.wallets.len(), 1);

        // check if wallet is locked
        let mut wallet = wm
            .get_wallet(wallet.get_chain(), wallet.get_address())
            .unwrap();
        assert!(wallet.is_locked());
        assert!(wallet.get_private_key().is_empty());

        // unlock wallet
        let result = wallet.unlock("password".to_owned());
        assert!(result.is_ok());
        assert_eq!(wallet.get_private_key(), test_privete_key);
    }

    #[test]
    fn test_wallet_manager_wallet_timing() {
        let default_password = "password".to_string();
        const WALLET_COUNT: usize = 10;

        let start_time = std::time::Instant::now();
        let mut wm = WalletManager::new();
        println!("New Manger: {:?}", start_time.elapsed());

        let start_time = std::time::Instant::now();
        for _ in 0..WALLET_COUNT {
            let wallet = Wallet::new(Chain::KLV).unwrap();
            _ = wm.add_wallet(wallet.to_owned(), default_password.to_owned());
        }
        println!("{} New Wallets: {:?}", WALLET_COUNT, start_time.elapsed());

        // lock wallet manager with WALLET_COUNT wallets
        let start_time = std::time::Instant::now();
        let result = wm.lock(default_password.to_owned());
        assert!(result.is_ok());
        println!(
            "Lock {} New Wallets: {:?}",
            WALLET_COUNT,
            start_time.elapsed()
        );

        // unlock wallet manager
        let start_time = std::time::Instant::now();
        let result = wm.unlock(default_password.to_owned());
        assert!(result.is_ok());
        println!(
            "Unlock Wallet Manager with {} wallets: {:?}",
            WALLET_COUNT,
            start_time.elapsed()
        );

        // lock wallet manager with WALLET_COUNT wallets all locked
        let start_time = std::time::Instant::now();
        let result = wm.lock(default_password.to_owned());
        assert!(result.is_ok());
        println!(
            "Lock {} New Wallets all locked: {:?}",
            WALLET_COUNT,
            start_time.elapsed()
        );

        // export wallet manager
        let start_time = std::time::Instant::now();
        let pem = wm.export(default_password.to_owned()).unwrap();
        println!(
            "Export Wallet Manager with {} wallets: {:?}",
            WALLET_COUNT,
            start_time.elapsed()
        );
        println!("Pem size: {:?} bytes", pem.contents().len());

        // import wallet manager
        let start_time = std::time::Instant::now();
        let mut wm2 = WalletManager::import(pem).unwrap();
        println!(
            "Import Wallet Manager with {} wallets: {:?}",
            WALLET_COUNT,
            start_time.elapsed()
        );
        assert!(wm2.is_locked());
        assert_eq!(wm2.wallets.len(), 0);
        wm2.unlock(default_password.to_owned()).unwrap();
        assert_eq!(wm2.wallets.len(), WALLET_COUNT);
    }

    #[test]
    fn test_add_existent_wallet_should_fail() {
        let default_password = "password";

        let mut wm = WalletManager::new();
        let wallet = Wallet::new(Chain::KLV).unwrap();

        let result = wm.add_wallet(wallet.clone(), default_password.to_owned());
        assert!(result.is_ok());
        let result = wm.add_wallet(wallet.clone(), default_password.to_owned());
        assert_eq!(
            result.err(),
            Some(Error::WalletManagerError(
                "Wallet already exists".to_string()
            ))
        );
    }

    #[test]
    fn test_set_mnemonic_should_work() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();

        let result = wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_mnemonic_should_fail() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();

        let result = wm.set_mnemonic("invalid mnemonic".to_string(), default_password);
        assert_eq!(
            result.err(),
            Some(Error::InvalidMnemonic("Invalid mnemonic"))
        );
    }

    #[test]
    fn test_set_mnemonic_already_set_should_fail() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();

        let result = wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password.clone());
        assert!(result.is_ok());

        let result = wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password);
        assert_eq!(
            result.err(),
            Some(Error::WalletManagerError(
                "Default mnemonic already exists".to_string()
            ))
        );
    }

    #[test]
    fn test_get_mnemonic_not_set_should_fail() {
        let default_password = "password".to_string();

        let wm = WalletManager::new();
        let result = wm.get_mnemonic(default_password);
        assert_eq!(
            result.err(),
            Some(Error::WalletManagerError(
                "Default mnemonic not found".to_string()
            ))
        );
    }

    #[test]
    fn test_get_mnemonic_should_work() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();

        let result = wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password.clone());
        assert!(result.is_ok());

        let result = wm.get_mnemonic(default_password);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DEFAULT_MNEMONIC);
    }

    #[test]
    fn test_get_mnemonic_wallet() {
        let default_password = "password".to_string();

        let mut wm = WalletManager::new();

        let result = wm.set_mnemonic(DEFAULT_MNEMONIC.to_string(), default_password.clone());
        assert!(result.is_ok());

        let mut w_default = wm.wallets.get(KOS_WM_TAG_DEFAULT).unwrap().to_owned();
        assert!(w_default.is_locked());
        // get mnemonic shoudl be empty
        let result = w_default.get_mnemonic();
        assert_eq!(result, "");

        // unlock wallet and retrive mnemonic
        let _ = w_default.unlock(default_password);
        let result = w_default.get_mnemonic();
        assert_eq!(result, DEFAULT_MNEMONIC);
    }
}
