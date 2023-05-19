use crate::{
    chain::{BaseChain, Chain},
    models::BroadcastResult,
};

use kos_crypto::keypair::KeyPair;
use kos_types::{error::Error, number::BigNumber};

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
    keypair: KeyPair,
    chain: Chain,
    public_address: String,
    node_url: String,
}

#[wasm_bindgen]
// wallet contructors
impl Wallet {
    // strean`() encode wallet pem

    /// lock wallet privatekey with password
    pub fn lock(_password: String) {
        todo!()
    }
    /// unlock wallet privatekey with password
    pub fn unlock(_password: String) {
        todo!()
    }

    #[wasm_bindgen(constructor)]
    /// create a random private key wallet
    pub fn new(chain: Chain) -> Result<Wallet, Error> {
        let kp = chain.new_keypair().unwrap();
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            account_type: AccountType::PrivateKey,
            mnemonic: String::new(),
            path: String::new(),
            keypair: kp,
            chain: chain,
            public_address: address,
            node_url: chain.base_chain().node_url.to_string(),
        })
    }

    #[wasm_bindgen(js_name = "fromKeyPair")]
    /// restore wallet from keypair
    pub fn from_keypair(chain: Chain, kp: KeyPair) -> Result<Wallet, Error> {
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            account_type: AccountType::PrivateKey,
            mnemonic: String::new(),
            path: String::new(),
            keypair: kp,
            chain: chain,
            public_address: address,
            node_url: chain.base_chain().node_url.to_string(),
        })
    }

    #[wasm_bindgen(js_name = "fromMnemonic")]
    /// restore wallet from mnemonic
    pub fn from_mnemonic(
        chain: Chain,
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<Wallet, Error> {
        let kp = chain
            .keypair_from_mnemonic(mnemonic, path, password)
            .unwrap();
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            account_type: AccountType::Mnemonic,
            mnemonic: mnemonic.to_string(),
            path: path.to_string(),
            keypair: kp,
            chain: chain,
            public_address: address,
            node_url: chain.base_chain().node_url.to_string(),
        })
    }
}

#[wasm_bindgen]
// wallet properties
impl Wallet {
    #[wasm_bindgen(js_name = "getChain")]
    /// get wallet chain type
    pub fn get_chain(&self) -> Chain {
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
    pub fn get_public_key(&self) -> String {
        self.keypair.public_key_hex()
    }

    #[wasm_bindgen(js_name = "getPath")]
    /// get wallet path if wallet is created from mnemonic
    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    #[wasm_bindgen(js_name = "getPrivateKey")]
    /// get wallet private key
    pub fn get_private_key(&self) -> String {
        self.keypair.secret_key_hex()
    }

    #[wasm_bindgen(js_name = "getMnemonic")]
    /// get wallet mnemonic if wallet is created from mnemonic
    pub fn get_mnemonic(&self) -> String {
        self.mnemonic.clone()
    }

    #[wasm_bindgen(js_name = "getNodeUrl")]
    /// get node url setting for wallet
    pub fn get_node_url(&self) -> String {
        self.node_url.clone()
    }

    #[wasm_bindgen(js_name = "setNodeUrl")]
    /// set node url setting for wallet
    pub fn set_node_url(&mut self, node_url: String) {
        self.node_url = node_url.clone();
    }
}

#[wasm_bindgen]
// wallet methods
impl Wallet {
    #[wasm_bindgen(js_name = "getBaseChain")]
    /// sign message with private key
    pub fn base_chain(&self) -> Result<BaseChain, Error> {
        Ok(self.chain.base_chain())
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// sign message with keypair
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.chain.sign_message(message, &self.keypair)
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// sign digest with keypait
    pub fn sign_digest(&self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        self.chain.sign_digest(hash, &self.keypair)
    }
}

#[wasm_bindgen]
impl Wallet {
    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        &self,
        address: &str,
        token: Option<String>,
    ) -> Result<BigNumber, Error> {
        self.chain
            .get_balance(address, token, Some(self.node_url.clone()))
            .await
    }

    #[wasm_bindgen(js_name = "broadcast")]
    /// boradcast transaction to network
    pub async fn broadcast(&self, data: Vec<u8>) -> Result<BroadcastResult, Error> {
        self.chain
            .broadcast(data, Some(self.node_url.clone()))
            .await
    }
}
