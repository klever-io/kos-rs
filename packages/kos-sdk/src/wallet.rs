use crate::{
    chain::{BaseChain, Chain},
    models::{self, BroadcastResult, Transaction},
};

use kos_crypto::keypair::KeyPair;
use kos_types::{error::Error, number::BigNumber};

use bincode;
use pem::{encode as encode_pem, parse as parse_pem, Pem};
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
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Wallet {
    chain: Chain,
    account_type: AccountType,
    public_address: String,
    is_locked: bool,

    encrypted_data: Option<Vec<u8>>,
    mnemonic: Option<String>,
    path: Option<String>,
    keypair: Option<KeyPair>,
    node_url: Option<String>,
}

#[wasm_bindgen]
// wallet contructors
impl Wallet {
    // strean`() encode wallet pem

    /// lock wallet privatekey with password
    pub fn lock(&mut self, password: String) -> Result<(), Error> {
        if let Some(ref encrypted_data) = self.encrypted_data {
            // verify password
            // decrypt encrypted_data
            _ = kos_crypto::cipher::decrypt(encrypted_data, &password)?;
        } else {
            // encrypt if encrypted_data is none serialize wallet
            let serialized =
                bincode::serialize(&self).map_err(|e| Error::CipherError(e.to_string()))?;
            // encrypt and encode
            let data = kos_crypto::cipher::encrypt(&serialized, &password)?;
            // save to encrypted_data
            self.encrypted_data = Some(data.clone());
        }

        // reset secrets
        self.keypair = None;
        self.mnemonic = None;
        self.path = None;
        self.node_url = None;
        self.is_locked = true;

        Ok(())
    }

    /// unlock wallet privatekey with password
    pub fn unlock(&mut self, password: String) -> Result<(), Error> {
        // check if is locked and data exists
        if !self.is_locked {
            return Err(Error::WalletManagerError(
                "Wallet is not locked".to_string(),
            ));
        }
        let encrypted_data = match self.encrypted_data {
            Some(ref data) => data,
            None => return Err(Error::WalletManagerError("No encrypted data".to_string())),
        };
        // decrypt encrypted_data
        let data = kos_crypto::cipher::decrypt(encrypted_data, &password)?;
        // resore values
        let wallet: Wallet = bincode::deserialize(&data)
            .map_err(|e| Error::CipherError("deserialize data".to_string()))?;
        // restore secrets
        self.keypair = wallet.keypair;
        self.mnemonic = wallet.mnemonic;
        self.path = wallet.path;
        self.node_url = wallet.node_url;
        self.is_locked = true;
        self.is_locked = false;

        Ok(())
    }

    #[wasm_bindgen(js_name = "isLocked")]
    /// check if wallet is locked
    pub fn is_locked(&self) -> bool {
        return self.is_locked;
    }

    #[wasm_bindgen(js_name = "verifyPassword")]
    pub fn verify_password(&self, password: String) -> Result<(), Error> {
        match self.encrypted_data {
            Some(ref encrypted_data) => {
                // verify password
                // decrypt encrypted_data
                _ = kos_crypto::cipher::decrypt(encrypted_data, &password)?;
            }
            None => return Err(Error::WalletManagerError("No encrypted data".to_string())),
        }

        Ok(())
    }

    #[wasm_bindgen(constructor)]
    /// create a random private key wallet
    pub fn new(chain: Chain) -> Result<Wallet, Error> {
        let kp = chain.new_keypair()?;

        Wallet::from_keypair(chain, kp)
    }

    #[wasm_bindgen(js_name = "fromKeyPair")]
    /// restore wallet from keypair
    pub fn from_keypair(chain: Chain, kp: KeyPair) -> Result<Wallet, Error> {
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            chain: chain,
            account_type: AccountType::PrivateKey,
            public_address: address,
            is_locked: false,

            encrypted_data: None,
            mnemonic: Some(String::new()),
            path: Some(String::new()),
            keypair: Some(kp),
            node_url: Some(chain.base_chain().node_url.to_string()),
        })
    }

    #[wasm_bindgen(js_name = "fromMnemonic")]
    /// restore wallet from mnemonic
    pub fn from_mnemonic(
        chain: Chain,
        mnemonic: String,
        path: String,
        password: Option<String>,
    ) -> Result<Wallet, Error> {
        let kp = chain.keypair_from_mnemonic(&mnemonic, &path, password)?;
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            chain: chain,
            account_type: AccountType::Mnemonic,
            public_address: address,
            is_locked: false,

            encrypted_data: None,
            mnemonic: Some(mnemonic),
            path: Some(path),
            keypair: Some(kp),
            node_url: Some(chain.base_chain().node_url.to_string()),
        })
    }

    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(data: String) -> Result<Wallet, Error> {
        // parse pem
        let pem = parse_pem(&data)
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        Wallet::import(pem)
    }

    #[wasm_bindgen(js_name = "toPem")]
    pub fn to_pem(&self, password: String) -> Result<Vec<u8>, Error> {
        let pem = self.export(password)?;

        Ok(encode_pem(&pem).as_bytes().to_vec())
    }
}

// wallet properties
impl Wallet {
    pub fn import(pem: Pem) -> Result<Wallet, Error> {
        // Deserialize decrypted bytes to WalletManager
        let wallet: Wallet = bincode::deserialize(pem.contents())
            .map_err(|e| Error::CipherError(format!("deserialize data: {}", e.to_string())))?;

        //check tag
        if pem.tag() != wallet.public_address {
            return Err(Error::WalletManagerError("Invalid PEM tag".to_string()));
        }

        Ok(wallet)
    }

    pub fn export(&self, password: String) -> Result<Pem, Error> {
        // validate password and lock wallet
        if !self.is_locked() {
            return Err(Error::WalletManagerError(
                "Wallet is not locked".to_string(),
            ));
        }

        self.verify_password(password)?;

        // serialize wallet manager
        let serialized = bincode::serialize(self).map_err(|e| Error::CipherError(e.to_string()))?;
        let pem = kos_crypto::cipher::to_pem(self.public_address.to_owned(), &serialized)?;

        Ok(pem)
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
        match self.keypair {
            Some(ref kp) => kp.public_key_hex(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "getPath")]
    /// get wallet path if wallet is created from mnemonic
    pub fn get_path(&self) -> String {
        match self.path {
            Some(ref path) => path.clone(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "getPrivateKey")]
    /// get wallet private key
    pub fn get_private_key(&self) -> String {
        match self.keypair {
            Some(ref kp) => kp.secret_key_hex(),
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

    #[wasm_bindgen(js_name = "getNodeUrl")]
    /// get node url setting for wallet
    pub fn get_node_url(&self) -> String {
        match self.node_url {
            Some(ref node_url) => node_url.clone(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "setNodeUrl")]
    /// set node url setting for wallet
    pub fn set_node_url(&mut self, node_url: String) {
        self.node_url = Some(node_url.clone());
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
        if self.is_locked {
            return Err(Error::WalletManagerError("Wallet is locked".to_string()));
        }

        match self.keypair {
            Some(ref kp) => self.chain.sign_message(message, kp),
            None => Err(Error::WalletManagerError("no keypair".to_string())),
        }
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// sign digest with keypait
    pub fn sign_digest(&self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        if self.is_locked {
            return Err(Error::WalletManagerError("Wallet is locked".to_string()));
        }

        match self.keypair {
            Some(ref kp) => self.chain.sign_digest(hash, kp),
            None => Err(Error::WalletManagerError("no keypair".to_string())),
        }
    }

    #[wasm_bindgen(js_name = "sign")]
    pub fn sign(&self, tx: Transaction) -> Result<Transaction, Error> {
        if self.is_locked {
            return Err(Error::WalletManagerError("Wallet is locked".to_string()));
        }

        match self.keypair {
            Some(ref kp) => self.chain.sign(tx, kp),
            None => Err(Error::WalletManagerError("no keypair".to_string())),
        }
    }
}

#[wasm_bindgen]
impl Wallet {
    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        &self,
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        self.chain
            .get_balance(address, token, node_url.or(self.node_url.clone()))
            .await
    }

    #[wasm_bindgen(js_name = "send")]
    /// create a send transaction network
    pub async fn send(
        &self,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        self.chain
            .send(
                self.get_address(),
                receiver,
                amount,
                options,
                node_url.or(self.node_url.clone()),
            )
            .await
    }

    #[wasm_bindgen(js_name = "broadcast")]
    /// boradcast transaction to network
    pub async fn broadcast(
        &self,
        data: Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        self.chain
            .broadcast(data, node_url.or(self.node_url.clone()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::from_utf8;

    #[test]
    fn test_sign_broadcast() {
        let mut w1 = Wallet::from_mnemonic(
            Chain::KLV,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        Chain::KLV.get_path(0).unwrap(),
            None,
        ).unwrap();

        w1.set_node_url("https://node.testnet.klever.finance".to_string());

        let tx = tokio_test::block_on(w1.send(
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm".to_string(),
            BigNumber::from(10),
            None,
            None,
        ))
        .unwrap();

        let to_broadcast = w1.sign(tx).unwrap();
        let result = tokio_test::block_on(w1.broadcast(to_broadcast, None));

        assert!(result.is_ok())
    }

    #[test]
    fn test_export_import() {
        let default_password = "password";
        // create wallet
        let mut w1 = Wallet::from_mnemonic(
            Chain::KLV,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        Chain::KLV.get_path(0).unwrap(),
            None,
        ).unwrap();

        // check if wallet is unlocked (nearly created wallet)
        assert!(!w1.is_locked());
        // lock wallet
        let result = w1.lock(default_password.to_string());
        assert!(result.is_ok());
        assert!(w1.is_locked());
        // check if secret keys are removed
        assert!(w1.get_private_key().is_empty());
        assert!(w1.get_mnemonic().is_empty());
        assert!(w1.get_path().is_empty());

        // export wallet
        let result = w1.to_pem(default_password.to_string());
        assert!(result.is_ok());

        // export wrong password
        let result = w1.to_pem("wrong password".to_string());
        assert!(result.is_err());

        // unlock wallet
        let result = w1.unlock(default_password.to_string());
        assert!(result.is_ok());
        assert!(!w1.is_locked());
        // check if secret keys restored
        assert_eq!(
            w1.get_private_key(),
            "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d"
        );
        assert_eq!(w1.get_mnemonic(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert_eq!(w1.get_path(), "m/44'/690'/0'/0'/0'");

        // try to export wallet unlocked
        let result = w1.export(default_password.to_string());
        assert!(result.is_err());

        // try to lock with wrong password
        let result = w1.lock("wrong password".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_import_pem() {
        let pem_str =
            "-----BEGIN klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy-----
AQAAAAAAAAA+AAAAAAAAAGtsdjF1c2RueXdqaHJsdjR0Y3l1NnN0eHBsNnl2aHBs
ZzM1bmVwbGpsdDR5NXI3eXBwZThlcjRxdWpsYXp5AQGRAQAAAAAAAIGO1zP0NFHP
eWqKpFirMyd6447Ru4Ge+QQUcvJ+7BiZvKWrmOsmovHNsNPl36Nep8Jt9meVY49b
eZDvpgEu8dqIgC9FPzasv+4Ba043sPdbakGpXjD7eNQtWuq0thh8sNQDnu49LlA7
X8iUZYBjglGbhXpqvTKRTQ4nlHCqw5M5zE2eLxXZcUQ381FGWIXzAhRe5Ya9G++/
K8z5qqJ6j8oyG1lmkFygaXWbTakrOplppRR7fm627LtFqJ3CIAGq0sY1VDbtw6tH
Zq13rjzHYE3ld+ZP+5ZNo4VX4EBnpROXzQ+E0+kswfF0fSi5xAtX8j/MVeAK8cp1
6pplxOwH5Fi3xQlnjxz0DtyBkk9CFW2ZlOIQMxJeupwGGxHWNq/Z4S7c0yQNO6WP
AG7td4nq+/6KDJBXO2vBEzxwPIXks8kJ62QPJJ2SjgJzHnv6DE+8l8W/xQi/t4/R
h0IUcrx6pulH79PWNPby8Rim03BXsDpPTUbLNARd6JG/vam/zHMMq54wAvEL2gqE
edMBaWzIqLE5AAAAAA==
-----END klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy-----";

        let wallet = Wallet::from_pem(pem_str.to_owned()).unwrap();
        assert!(wallet.is_locked());
        assert_eq!(
            wallet.get_address(),
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        )
    }
}
