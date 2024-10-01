use crate::{
    chain::{BaseChain, Chain},
    models::{self, BroadcastResult, PathOptions, Transaction},
};

use kos_crypto::keypair::KeyPair;
use kos_types::{error::Error, number::BigNumber};
use kos_utils::{pack, unpack};

use pem::{encode as encode_pem, parse as parse_pem, Pem};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};

use kos_crypto::cipher::CipherAlgo;
use wasm_bindgen::prelude::*;

// todo!("allow change of default algo")
const DEFAULT_ALGO: CipherAlgo = kos_crypto::cipher::CipherAlgo::GMC;
// todo!("implement wallet auto lock")

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
    chain: Chain,
    account_type: AccountType,
    public_address: String,
    is_locked: bool,
    node_url: Option<String>,
    index: Option<u32>,

    encrypted_data: Option<Vec<u8>>,
    mnemonic: Option<String>,
    path: Option<String>,
    keypair: Option<KeyPair>,
}

#[wasm_bindgen]
impl Wallet {
    pub fn wallet_key(chain: crate::chain::Chain, address: &str) -> String {
        format!("{}-{}", chain.base_chain().symbol, address)
    }

    pub fn get_key(&self) -> String {
        Wallet::wallet_key(self.chain, &self.public_address)
    }

    /// lock wallet privatekey with password
    pub fn lock(&mut self, password: String) -> Result<(), Error> {
        // return if is locked
        if self.is_locked {
            return Ok(());
        }

        // Verify password if encrypted_data is present, else serialize and encrypt wallet
        match self.encrypted_data {
            Some(_) => self.verify_password(password.clone())?,
            None => {
                let serialized = pack(self)?;

                let encrypted_data =
                    kos_crypto::cipher::encrypt(DEFAULT_ALGO, &serialized, &password)?;
                self.encrypted_data = Some(encrypted_data);
            }
        }

        // reset secrets
        self.keypair = None;
        self.mnemonic = None;
        self.path = None;
        self.is_locked = true;

        Ok(())
    }

    /// unlock wallet privatekey with password
    pub fn unlock(&mut self, password: String) -> Result<(), Error> {
        // return if is unlocked
        if !self.is_locked {
            return Ok(());
        }

        let encrypted_data = match self.encrypted_data {
            Some(ref data) => data,
            None => return Err(Error::WalletManagerError("No encrypted data".to_string())),
        };
        // decrypt encrypted_data
        let data = kos_crypto::cipher::decrypt(encrypted_data, &password)?;
        // restore values
        let wallet: Wallet =
            unpack(&data[..]).map_err(|e| Error::CipherError(format!("deserialize: {}", e)))?;

        // restore secrets
        self.keypair = wallet.keypair;
        self.mnemonic = wallet.mnemonic;
        self.path = wallet.path;
        self.is_locked = false;

        Ok(())
    }

    #[wasm_bindgen(js_name = "isLocked")]
    /// check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    #[wasm_bindgen(js_name = "verifyPassword")]
    pub fn verify_password(&self, password: String) -> Result<(), Error> {
        match self.encrypted_data {
            Some(ref encrypted_data) => {
                // verify password
                // decrypt encrypted_data
                _ = kos_crypto::cipher::decrypt(encrypted_data, &password)?;

                Ok(())
            }
            None => Err(Error::WalletManagerError("No encrypted data".to_string())),
        }
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
            chain,
            account_type: AccountType::PrivateKey,
            public_address: address,
            is_locked: false,
            node_url: None,
            index: None,

            encrypted_data: None,
            mnemonic: Some(String::new()),
            path: Some(String::new()),
            keypair: Some(kp),
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
        // validate mnemonic entropy
        kos_crypto::mnemonic::validate_mnemonic(&mnemonic)?;

        let kp = chain.keypair_from_mnemonic(&mnemonic, &path, password)?;
        let address = chain.get_address_from_keypair(&kp)?;

        Ok(Wallet {
            chain,
            account_type: AccountType::Mnemonic,
            public_address: address,
            is_locked: false,
            node_url: None,
            index: None,

            encrypted_data: None,
            mnemonic: Some(mnemonic),
            path: Some(path),
            keypair: Some(kp),
        })
    }

    #[wasm_bindgen(js_name = "fromPrivateKey")]
    /// restore wallet from mnemonic
    pub fn from_private_key(chain: Chain, private_key: String) -> Result<Wallet, Error> {
        // convert hex to bytes
        let private_key = hex::decode(private_key)?;

        // check size of private key
        if private_key.len() != 32 {
            return Err(Error::WalletManagerError("Invalid private key".to_string()));
        }

        // crete keypair from private key
        let kp = chain.keypair_from_bytes(&private_key)?;

        // create wallet from keypair
        Wallet::from_keypair(chain, kp)
    }

    #[wasm_bindgen(js_name = "fromKCPem")]
    /// restore wallet from mnemonic
    pub fn from_kc_pem(chain: Chain, data: &[u8]) -> Result<Wallet, Error> {
        // decode pem file
        let pem = parse_pem(data)
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        let content = String::from_utf8(pem.contents().to_vec())
            .map_err(|_| Error::WalletManagerError("Invalid PEM data".to_string()))?;

        let pk_hex = content.chars().take(64).collect::<String>();

        // import from private key
        Wallet::from_private_key(chain, pk_hex)
    }

    #[wasm_bindgen(js_name = "fromMnemonicIndex")]
    /// restore wallet from mnemonic
    pub fn from_mnemonic_index(
        chain: Chain,
        mnemonic: String,
        path_options: &PathOptions,
        password: Option<String>,
    ) -> Result<Wallet, Error> {
        let path = chain.get_path(path_options)?;
        let mut wallet = Wallet::from_mnemonic(chain, mnemonic, path, password)?;
        wallet.index = Some(path_options.index);

        Ok(wallet)
    }

    #[wasm_bindgen(js_name = "fromPem")]
    pub fn from_pem(data: &[u8]) -> Result<Wallet, Error> {
        // parse pem
        let pem = parse_pem(data)
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
        let wallet: Wallet = unpack(pem.contents())
            .map_err(|e| Error::CipherError(format!("deserialize data: {}", e)))?;

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
        let serialized = pack(self)?;

        let pem = kos_crypto::cipher::to_pem(self.get_key(), &serialized)?;

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
        match self.keypair {
            Some(ref kp) => kp.secret_key_hex(),
            None => String::new(),
        }
    }

    #[wasm_bindgen(js_name = "getKeypair")]
    pub fn get_keypair(&self) -> Option<KeyPair> {
        self.keypair.clone()
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
            None => crate::utils::get_node_url(self.chain.base_chain().symbol),
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
    /// sign digest with raw keypair
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
    /// broadcast transaction to network
    pub async fn broadcast(
        &self,
        data: Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        self.chain
            .broadcast(data, node_url.or(self.node_url.clone()))
            .await
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        &self,
        address: &str,
        option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        self.chain.validate_address(address, option)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_broadcast() {
        let mut w1 = Wallet::from_mnemonic(
            Chain::KLV,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        Chain::KLV.get_path(&PathOptions::new(0)).unwrap(),
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
        Chain::KLV.get_path(&PathOptions::new(0)).unwrap(),
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
        let pem = result.unwrap();
        println!("{}", String::from_utf8(pem.clone()).unwrap());

        // export wrong password
        let result = w1.to_pem("wrong password".to_string());
        assert!(result.is_err());

        // unlock wallet
        let result = w1.unlock(default_password.to_string());
        println!("{:?}", result);
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
            "-----BEGIN KLV-klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy-----
AQA+a2x2MXVzZG55d2pocmx2NHRjeXU2c3R4cGw2eXZocGxnMzVuZXBsamx0NHk1
cjd5cHBlOGVyNHF1amxhenkBAAABvAIAOJCsBrwdU4FmaoxoUm790L+QMK4zTixR
pX8Nich/FhH53iI1cgoAyySPnzUVpvdSrsYZgpALJHO1Iv5FYBMYOqIIOJfLgMYp
N4C8Qw2LCgx4L/VIFoU+nbxJhvnx8Xd9mmkyWhbcoBSAHxzQ/teEfTRAMu9l8H33
tN5xf3N7KRFsjZ3vDSW9w/xoiOCsi1QbTpE7SHB0KGLPaW1kgJ57J0gPC1QHI8Nk
csPM/08jVmOb1OIIs51qmo/FOsewPwb5aPEji6panHN3aJiYYv5XZCAxbWQqu2oY
Q4mznxvSHZLyGLsTGDmrticCzCL2i+3nXh7a07PsTMguY8IqUNRZpF68TqcYw/Bf
56tx4+0OgQ2ujSMWWeR3uN95K6o7rzIMpRbLxrcGfTkfozbGMe/H0Ur+5YI0hVY/
qeVTAAAA
-----END KLV-klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy-----";

        let wallet = Wallet::from_pem(pem_str.as_bytes()).unwrap();
        assert!(wallet.is_locked());
        assert_eq!(
            wallet.get_address(),
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        )
    }

    #[test]
    fn test_wallet_mnemonic_without_index() {
        let w1 = Wallet::from_mnemonic(
            Chain::KLV,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        Chain::KLV.get_path(&PathOptions::new(0)).unwrap(),
            None,
        ).unwrap();

        let result = w1.get_index();
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_mnemonic_with_index() {
        let w1 = Wallet::from_mnemonic_index(
            Chain::KLV,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        &PathOptions::new(10),
            None,
        ).unwrap();
        let result = w1.get_index();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_validate_address_ok() {
        let list_klv = [
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "klv1x2ejsdqz8uccl7htu4cef63z0cqnydhkd8g36tgk6qdv94hu7syqms3spm",
        ];

        let list_btc = [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
        ];

        let w1 = Wallet::new(Chain::KLV).unwrap();

        for address in list_klv.iter() {
            let result = w1.validate_address(address, None);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }

        let w2 = Wallet::new(Chain::BTC).unwrap();
        for address in list_btc.iter() {
            let result = w2.validate_address(address, None);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
    }

    #[test]
    fn test_validate_address_fail() {
        let list_klv = [
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlaz",
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy1",
            "klv2usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "klvusdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy",
            "bnb1ztx5rf7jx28k3xnemftcq3kfgm3yhfvfmhm456",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        ];

        let list_btc = [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qgl5vlg0zdl7yvprgxj9fevsc6q6x5dmcyk3cn3",
        ];

        let w1 = Wallet::new(Chain::KLV).unwrap();

        for address in list_klv.iter() {
            let result = w1.validate_address(address, None);
            assert!(result.is_ok());
            assert!(!result.unwrap());
        }

        let w2 = Wallet::new(Chain::BTC).unwrap();
        for address in list_btc.iter() {
            let result = w2.validate_address(
                address,
                Some(models::AddressOptions::new(
                    Some("0B110907".to_string()),
                    None,
                    None,
                )),
            );
            assert!(result.is_ok());
            assert!(!result.unwrap());
        }
    }
}
