pub mod models;
pub mod number;
pub mod signer;

use crate::models::{
    convert_tx_options, wallet_options_to_chain_type, TransactionChainOptions, WalletOptions,
};
use hex::ToHex;
use kos::chains::{get_chain_by_base_id, get_chain_by_params, Chain, Transaction};
use kos::crypto::cipher;
use kos::crypto::cipher::CipherAlgo;
use kos_codec::KosCodedAccount;
use kos_codec::{encode_for_broadcast, encode_for_signing};
use wasm_bindgen::prelude::*;

mod error;
use error::KOSError;

#[wasm_bindgen]
pub struct KOSAccount {
    pub chain_id: u32,
    private_key: String,
    public_key: String,
    address: String,
    path: String,
    options: Option<WalletOptions>,
}

#[allow(unused)]
#[wasm_bindgen]
impl KOSAccount {
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> String {
        self.private_key.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_private_key(&mut self, pbk: String) {
        self.private_key = pbk;
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_public_key(&mut self, pbk: String) {
        self.public_key = pbk;
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_address(&mut self, addr: String) {
        self.address = addr;
    }

    #[wasm_bindgen(getter)]
    pub fn options(&self) -> Option<WalletOptions> {
        self.options.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_path(&mut self, val: String) {
        self.path = val;
    }

    #[wasm_bindgen(setter)]
    pub fn set_options(&mut self, opt: Option<WalletOptions>) {
        self.options = opt;
    }
}

#[wasm_bindgen]
pub struct KOSTransaction {
    pub chain_id: u32,
    raw: String,
    sender: String,
    signature: String,
}

#[wasm_bindgen]
impl KOSTransaction {
    #[wasm_bindgen(getter)]
    pub fn raw(&self) -> String {
        self.raw.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_raw(&mut self, raw: String) {
        self.raw = raw;
    }

    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> String {
        self.sender.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_sender(&mut self, sender: String) {
        self.sender = sender;
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> String {
        self.signature.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[wasm_bindgen]
pub fn generate_mnemonic(size: i32) -> Result<String, KOSError> {
    Ok(kos::crypto::mnemonic::generate_mnemonic(size as usize)?.to_phrase())
}

#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: String) -> bool {
    kos::crypto::mnemonic::validate_mnemonic(mnemonic.as_str()).is_ok()
}

#[wasm_bindgen]
pub fn get_path_by_chain(
    chain_id: u32,
    index: u32,
    use_legacy_path: bool,
) -> Result<String, KOSError> {
    let chain = get_chain_by(chain_id)?;
    let path = chain.get_path(index, use_legacy_path);
    Ok(path)
}

#[wasm_bindgen]
pub fn generate_wallet_from_mnemonic(
    mnemonic: String,
    chain_id: u32,
    index: u32,
    options: Option<WalletOptions>,
) -> Result<KOSAccount, KOSError> {
    if !validate_mnemonic(mnemonic.clone()) {
        return Err(KOSError::kos_delegate("Invalid mnemonic".to_string()));
    }

    let chain_params = wallet_options_to_chain_type(chain_id, &options);

    let chain = get_chain_by_params(chain_params)
        .ok_or_else(|| KOSError::unsupported_chain(chain_id.to_string()))?;

    let use_legacy_path = options.as_ref().is_some_and(|opt| opt.use_legacy_path);

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
        options,
    })
}

#[wasm_bindgen]
pub fn generate_wallet_from_private_key(
    chain_id: u32,
    private_key: String,
    options: Option<WalletOptions>,
) -> Result<KOSAccount, KOSError> {
    let chain_params = wallet_options_to_chain_type(chain_id, &options);

    let chain = get_chain_by_params(chain_params)
        .ok_or_else(|| KOSError::unsupported_chain(chain_id.to_string()))?;

    let public_key = chain.get_pbk(hex::decode(private_key.clone())?)?;
    let address = chain.get_address(public_key.clone())?;

    Ok(KOSAccount {
        chain_id,
        private_key: private_key.clone(),
        public_key: hex::encode(public_key.clone()),
        address,
        path: String::new(),
        options,
    })
}

#[wasm_bindgen]
pub fn encrypt_with_gcm(
    data: String,
    password: String,
    iterations: u32,
) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::GCM.encrypt(data.as_bytes(), password.as_str(), iterations)?;
    Ok(encrypted_data.encode_hex())
}

#[wasm_bindgen]
pub fn encrypt_with_cbc(
    data: String,
    password: String,
    iterations: u32,
) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::CBC.encrypt(data.as_bytes(), password.as_str(), iterations)?;
    Ok(encrypted_data.encode_hex())
}

#[wasm_bindgen]
pub fn encrypt_with_cfb(
    data: String,
    password: String,
    iterations: u32,
) -> Result<String, KOSError> {
    let encrypted_data = CipherAlgo::CFB.encrypt(data.as_bytes(), password.as_str(), iterations)?;
    Ok(encrypted_data.encode_hex())
}

#[wasm_bindgen]
pub fn decrypt(data: String, password: String, iterations: u32) -> Result<String, KOSError> {
    let data_in_byte = hex::decode(data)?;
    let decrypted_data = cipher::decrypt(&data_in_byte, password.as_str(), iterations)?;
    Ok(String::from_utf8_lossy(&decrypted_data).to_string())
}

fn get_chain_by(id: u32) -> Result<Box<dyn Chain>, KOSError> {
    let chain =
        get_chain_by_base_id(id).ok_or_else(|| KOSError::unsupported_chain(id.to_string()))?;

    Ok(chain)
}

#[wasm_bindgen]
pub fn sign_transaction(
    account: KOSAccount,
    raw: String,
    options: Option<TransactionChainOptions>,
) -> Result<KOSTransaction, KOSError> {
    let chain_options = convert_tx_options(options);

    let chain_params = wallet_options_to_chain_type(account.chain_id, &account.options);
    let chain = get_chain_by_params(chain_params)
        .ok_or_else(|| KOSError::unsupported_chain(account.chain_id.to_string()))?;

    let transaction = Transaction {
        raw_data: hex::decode(raw.clone())?,
        signature: Vec::new(),
        tx_hash: Vec::new(),
        options: chain_options,
    };

    let kos_codec_acc = KosCodedAccount {
        chain_id: account.chain_id,
        address: account.address.clone(),
        public_key: account.public_key.clone(),
    };

    let encoded = encode_for_signing(kos_codec_acc.clone(), transaction)?;
    let signed_transaction = chain.sign_tx(hex::decode(account.private_key.clone())?, encoded)?;
    let encoded_to_broadcast = encode_for_broadcast(kos_codec_acc, signed_transaction)?;

    Ok(KOSTransaction {
        chain_id: account.chain_id,
        raw: hex::encode(encoded_to_broadcast.raw_data),
        sender: account.address,
        signature: hex::encode(encoded_to_broadcast.signature),
    })
}

#[wasm_bindgen]
pub fn sign_message(account: KOSAccount, hex: String, legacy: bool) -> Result<Vec<u8>, KOSError> {
    let chain_params = wallet_options_to_chain_type(account.chain_id, &account.options);
    let chain = get_chain_by_params(chain_params)
        .ok_or_else(|| KOSError::unsupported_chain(account.chain_id.to_string()))?;
    let message = hex::decode(hex)?;

    let kos_codec_acc = KosCodedAccount {
        chain_id: account.chain_id,
        address: account.address.clone(),
        public_key: account.public_key.clone(),
    };

    let message_encoded = kos_codec::encode_for_sign_message(kos_codec_acc, message)?;

    let signature = chain.sign_message(
        hex::decode(account.private_key).unwrap(),
        message_encoded,
        legacy,
    )?;
    Ok(signature)
}

#[wasm_bindgen]
pub fn is_chain_supported(chain_id: u32) -> bool {
    kos::chains::is_chain_supported(chain_id)
}

#[wasm_bindgen]
pub fn get_supported_chains() -> Vec<u32> {
    kos::chains::get_supported_chains()
}
