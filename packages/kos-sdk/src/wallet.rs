use crate::chain::Chain;
use kos_crypto::{public::PublicKey, secret::SecretKey};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, EnumCount, IntoStaticStr)]
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
    account_type: AccountType,
    mnemonic: String,
    path: String,
    secret_key: SecretKey,
    chain: Chain,
    public_key: PublicKey,
    public_address: String,
}

#[wasm_bindgen]
impl Wallet {
    // locl wallet privatekey with password
    pub fn lock(_password: String) {
        todo!()
    }
    // unlock wallet privatekey with password
    pub fn unlock(_password: String) {
        todo!()
    }

    // create a random private key wallet
    pub fn new(chain: Chain) -> Result<Wallet, JsError> {
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let public_key = PublicKey::from(&secret_key);
        let address = chain.get_address_from_private_key(secret_key)?;

        Ok(Wallet {
            account_type: AccountType::PrivateKey,
            mnemonic: String::new(),
            path: String::new(),
            secret_key: secret_key,
            chain: chain,
            public_key: public_key,
            public_address: address,
        })
    }

    #[wasm_bindgen(js_name = "fromSecretKey")]
    // restore wallet from secrekey
    pub fn from_secret_key(chain: Chain, secret_key: SecretKey) -> Result<Wallet, JsError> {
        let public_key = PublicKey::from(&secret_key);
        let address = chain.get_address_from_private_key(secret_key)?;

        Ok(Wallet {
            account_type: AccountType::PrivateKey,
            mnemonic: String::new(),
            path: String::new(),
            secret_key: secret_key,
            chain: chain,
            public_key: public_key,
            public_address: address,
        })
    }

    #[wasm_bindgen(js_name = "fromMnemonic")]
    // restore wallet from mnemonic (todo!() add passphrase)
    pub fn from_mnemonic(chain: Chain, mnemonic: String, path: String) -> Result<Wallet, JsError> {
        let s = SecretKey::new_from_mnemonic_phrase_with_path(&mnemonic[..], &path[..]);
        let secret_key = s.unwrap();
        let public_key = PublicKey::from(&secret_key);
        let address = chain.get_address_from_private_key(secret_key)?;

        Ok(Wallet {
            account_type: AccountType::Mnemonic,
            mnemonic: mnemonic,
            path: path,
            secret_key: secret_key,
            chain: chain,
            public_key: public_key,
            public_address: address,
        })
    }

    #[wasm_bindgen(js_name = "getChain")]
    // get chain type
    pub fn get_chain(&self) -> Chain {
        self.chain
    }

    #[wasm_bindgen(js_name = "getAccountType")]
    // get account type
    pub fn get_account_type(&self) -> AccountType {
        self.account_type
    }

    #[wasm_bindgen(js_name = "getAddress")]
    // get address
    pub fn get_address(&self) -> String {
        self.public_address.clone()
    }

    #[wasm_bindgen(js_name = "getPublicKey")]
    // get public key
    pub fn get_public_key(&self) -> String {
        self.public_key.to_string()
    }

    #[wasm_bindgen(js_name = "getPath")]
    // get path
    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    #[wasm_bindgen(js_name = "getPrivateKey")]
    // get private key
    pub fn get_private_key(&self) -> String {
        self.secret_key.to_string()
    }

    #[wasm_bindgen(js_name = "getMnemonic")]
    // get mnemonic
    pub fn get_mnemonic(&self) -> String {
        self.mnemonic.clone()
    }
}
