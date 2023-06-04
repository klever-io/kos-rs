use crate::wallet::Wallet;
use kos_types::error::Error;

use pem::{
    encode as encode_pem, encode_many as encode_many_pem, parse as parse_pem,
    parse_many as parse_many_pem, Pem,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

const KOS_WM_TAG: &str = "KOS WALLET MANAGER";

#[wasm_bindgen]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalletManager {
    is_locked: bool,
    default_mn: Option<String>,
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
            default_mn: None,
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
    pub fn from_pem(data: String) -> Result<WalletManager, Error> {
        // parse pem
        let pem = parse_pem(&data)
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
        // reutrn if already unlocked
        if !self.is_locked() {
            return Ok(());
        }

        // verify password
        self.verify_password(password.clone())?;

        // reload encrypted wallets from encrypted_data
        let wallets = parse_many_pem(self.encrypted_data.as_ref().unwrap())
            .map_err(|_| Error::WalletManagerError("Invalid encrypted data".to_string()))?;

        // deerialize all wallets and save to encrypted_data
        for pem in wallets.iter() {
            let wallet = Wallet::import(pem.clone())?;
            self.wallets.insert(pem.tag().to_string(), wallet);
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

        // verify password if encrypted data is present, else encrypt and save data
        match self.encrypted_data {
            Some(_) => self.verify_password(password.clone())?,
            None => {
                let mut wallets: Vec<Pem> = Vec::new();
                // serialize all wallets and save to encrypted_data
                for (_, wallet) in self.wallets.iter_mut() {
                    if !wallet.is_locked() {
                        wallet.lock(password.clone())?;
                    }

                    let pem = wallet.export(password.clone())?;
                    wallets.push(pem);
                }

                let data = encode_many_pem(&wallets);
                self.encrypted_data = Some(data.as_bytes().to_vec());
                self.checksum = Some(
                    kos_crypto::cipher::create_checksum(&password)
                        .as_bytes()
                        .to_vec(),
                );
            }
        }

        // reset secrets
        self.wallets = HashMap::new();
        self.is_locked = true;

        Ok(())
    }
}

impl WalletManager {
    pub fn import(pem: Pem) -> Result<WalletManager, Error> {
        //check tag
        if pem.tag() != KOS_WM_TAG {
            return Err(Error::WalletManagerError("Invalid PEM tag".to_string()));
        }

        // Deserialize decrypted bytes to WalletManager
        let wm: WalletManager = bincode::deserialize(pem.contents())
            .map_err(|e| Error::CipherError(format!("deserialize data: {}", e.to_string())))?;

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

        // serialize wallet manager
        let data = bincode::serialize(self).map_err(|e| Error::CipherError(e.to_string()))?;
        let pem = kos_crypto::cipher::to_pem(KOS_WM_TAG.to_owned(), &data)?;

        Ok(pem)
    }
}

#[wasm_bindgen]
impl WalletManager {
    // todo!() save operation
    #[wasm_bindgen(js_name = "addWallet")]
    pub fn add_wallet(&mut self, wallet: Wallet) -> Result<(), Error> {
        let wallet_name = Wallet::wallet_key(wallet.get_chain(), wallet.get_address().as_str());
        self.wallets.insert(wallet_name, wallet);
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;

    #[test]
    fn test_wallet_manager_export_import() {
        let default_password = "password";

        let mut wm = WalletManager::new();
        let wallet = Wallet::new(Chain::KLV).unwrap();
        let result = wm.add_wallet(wallet.to_owned());
        assert!(result.is_ok());

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
        assert_eq!(wm2.wallets.len(), 1);

        // check if wallet address matches
        let wallet2 = wm2
            .get_wallet(wallet.get_chain(), wallet.get_address())
            .unwrap();
        assert_eq!(wallet2.get_address(), wallet.get_address());
    }

    #[test]
    fn test_wallet_manager_lock_unlock() {
        let default_password = "password";

        let mut wm = WalletManager::new();
        let wallet = Wallet::new(Chain::KLV).unwrap();
        let test_privete_key = wallet.get_private_key();

        let resul = wm.add_wallet(wallet.clone());
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
        let default_password = "password";
        const WALLET_COUNT: usize = 10;

        let start_time = std::time::Instant::now();
        let mut wm = WalletManager::new();
        println!("New Manger: {:?}", start_time.elapsed());

        let start_time = std::time::Instant::now();
        for _ in 0..WALLET_COUNT {
            let wallet = Wallet::new(Chain::KLV).unwrap();
            _ = wm.add_wallet(wallet.to_owned());
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
}
