use kos::chains::util::hex_string_to_vec;
use kos::chains::{ChainOptions, CustomChainType};
use kos::crypto::base64;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WalletChainOptionsType {
    None,
    CustomEth,
    CustomIcp,
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WalletChainOptions {
    pub kind: WalletChainOptionsType,
    pub chain_id: u32, // used when kind == CustomEth
    key_type: String,  // used when kind == CustomIcp ("ed25519" | "secp256k1")
}

#[wasm_bindgen]
impl WalletChainOptions {
    #[wasm_bindgen(getter)]
    pub fn key_type(&self) -> String {
        self.key_type.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_key_type(&mut self, val: String) {
        self.key_type = val;
    }

    pub fn new_eth(chain_id: u32) -> WalletChainOptions {
        WalletChainOptions {
            kind: WalletChainOptionsType::CustomEth,
            chain_id,
            key_type: String::new(),
        }
    }

    pub fn new_icp(key_type: String) -> WalletChainOptions {
        WalletChainOptions {
            kind: WalletChainOptionsType::CustomIcp,
            chain_id: 0,
            key_type,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WalletOptions {
    pub use_legacy_path: bool,
    specific: Option<WalletChainOptions>,
}

#[wasm_bindgen]
impl WalletOptions {
    #[wasm_bindgen(getter)]
    pub fn specific(&self) -> Option<WalletChainOptions> {
        self.specific.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_specific(&mut self, val: Option<WalletChainOptions>) {
        self.specific = val;
    }
}

#[wasm_bindgen]
pub fn new_wallet_options(use_legacy_path: bool) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: None,
    }
}

#[wasm_bindgen]
pub fn new_eth_wallet_options(use_legacy_path: bool, chain_id: u32) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: Some(WalletChainOptions::new_eth(chain_id)),
    }
}

#[wasm_bindgen]
pub fn new_icp_wallet_options(use_legacy_path: bool, key_type: String) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: Some(WalletChainOptions::new_icp(key_type)),
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionChainOptionsType {
    Evm,
    Btc,
    Substrate,
    Cosmos,
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TransactionChainOptions {
    pub kind: TransactionChainOptionsType,

    // --- EVM ---
    pub chain_id: u32,

    // --- BTC ---
    input_amounts: Vec<u64>,
    prev_scripts: Vec<Vec<u8>>,

    // --- Substrate ---
    call: Vec<u8>,
    era: Vec<u8>,
    pub nonce: u32,
    pub tip: u64,
    asset_id: Option<String>,
    block_hash: Vec<u8>,
    genesis_hash: Vec<u8>,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub app_id: Option<u32>,
    signed_extensions: Option<Vec<String>>,

    // --- Cosmos ---
    cosmos_chain_id: String,
    pub account_number: u64,
}

#[wasm_bindgen]
impl TransactionChainOptions {
    // --- BTC getters/setters ---
    #[wasm_bindgen(getter)]
    pub fn input_amounts(&self) -> Vec<u64> {
        self.input_amounts.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_input_amounts(&mut self, val: Vec<u64>) {
        self.input_amounts = val;
    }

    // --- Substrate getters/setters ---
    #[wasm_bindgen(getter)]
    pub fn call(&self) -> Vec<u8> {
        self.call.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_call(&mut self, val: Vec<u8>) {
        self.call = val;
    }

    #[wasm_bindgen(getter)]
    pub fn era(&self) -> Vec<u8> {
        self.era.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_era(&mut self, val: Vec<u8>) {
        self.era = val;
    }

    #[wasm_bindgen(getter)]
    pub fn asset_id(&self) -> Option<String> {
        self.asset_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_asset_id(&mut self, val: Option<String>) {
        self.asset_id = val;
    }

    #[wasm_bindgen(getter)]
    pub fn block_hash(&self) -> Vec<u8> {
        self.block_hash.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_block_hash(&mut self, val: Vec<u8>) {
        self.block_hash = val;
    }

    #[wasm_bindgen(getter)]
    pub fn genesis_hash(&self) -> Vec<u8> {
        self.genesis_hash.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_genesis_hash(&mut self, val: Vec<u8>) {
        self.genesis_hash = val;
    }

    #[wasm_bindgen(getter)]
    pub fn signed_extensions(&self) -> Option<Vec<String>> {
        self.signed_extensions.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_signed_extensions(&mut self, val: Option<Vec<String>>) {
        self.signed_extensions = val;
    }

    // --- Cosmos getters/setters ---
    #[wasm_bindgen(getter)]
    pub fn cosmos_chain_id(&self) -> String {
        self.cosmos_chain_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_cosmos_chain_id(&mut self, val: String) {
        self.cosmos_chain_id = val;
    }
}

// Default used to zero-fill unused variant fields
impl Default for TransactionChainOptions {
    fn default() -> Self {
        TransactionChainOptions {
            kind: TransactionChainOptionsType::Evm,
            chain_id: 0,
            input_amounts: vec![],
            prev_scripts: vec![],
            call: vec![],
            era: vec![],
            nonce: 0,
            tip: 0,
            asset_id: None,
            block_hash: vec![],
            genesis_hash: vec![],
            spec_version: 0,
            transaction_version: 0,
            app_id: None,
            signed_extensions: None,
            cosmos_chain_id: String::new(),
            account_number: 0,
        }
    }
}

#[wasm_bindgen]
pub fn new_evm_transaction_options(chain_id: u32) -> TransactionChainOptions {
    TransactionChainOptions {
        kind: TransactionChainOptionsType::Evm,
        chain_id,
        ..Default::default()
    }
}

#[wasm_bindgen]
pub fn new_bitcoin_transaction_options(
    input_amounts: Vec<u64>,
    prev_scripts: Vec<String>,
) -> TransactionChainOptions {
    let prev_scripts = prev_scripts
        .iter()
        .map(|s| base64::simple_base64_decode(s).unwrap_or_default())
        .collect();

    TransactionChainOptions {
        kind: TransactionChainOptionsType::Btc,
        input_amounts,
        prev_scripts,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn new_substrate_transaction_options(
    call: String,
    era: String,
    nonce: u32,
    tip: u64,
    asset_id: Option<String>,
    block_hash: String,
    genesis_hash: String,
    spec_version: u32,
    transaction_version: u32,
    app_id: Option<u32>,
    signed_extensions: Option<Vec<String>>,
) -> TransactionChainOptions {
    TransactionChainOptions {
        kind: TransactionChainOptionsType::Substrate,
        call: hex_string_to_vec(call.as_str()).unwrap_or_default(),
        era: hex_string_to_vec(era.as_str()).unwrap_or_default(),
        nonce,
        tip,
        asset_id,
        block_hash: hex_string_to_vec(block_hash.as_str()).unwrap_or_default(),
        genesis_hash: hex_string_to_vec(genesis_hash.as_str()).unwrap_or_default(),
        spec_version,
        transaction_version,
        app_id,
        signed_extensions,
        ..Default::default()
    }
}

#[wasm_bindgen]
pub fn new_cosmos_transaction_options(
    chain_id: String,
    account_number: u64,
) -> TransactionChainOptions {
    TransactionChainOptions {
        kind: TransactionChainOptionsType::Cosmos,
        cosmos_chain_id: chain_id,
        account_number,
        ..Default::default()
    }
}

pub fn wallet_options_to_chain_type(
    chain_id: u32,
    options: &Option<WalletOptions>,
) -> CustomChainType {
    match options {
        Some(opts) => match &opts.specific {
            Some(WalletChainOptions {
                kind: WalletChainOptionsType::CustomEth,
                chain_id: custom_chain_id,
                ..
            }) => CustomChainType::CustomEth(*custom_chain_id),
            Some(WalletChainOptions {
                kind: WalletChainOptionsType::CustomIcp,
                key_type,
                ..
            }) => CustomChainType::CustomIcp(key_type.clone()),
            _ => CustomChainType::NotCustomBase(chain_id),
        },
        None => CustomChainType::NotCustomBase(chain_id),
    }
}

pub fn convert_tx_options(options: Option<TransactionChainOptions>) -> Option<ChainOptions> {
    match options {
        Some(tco) => match tco.kind {
            TransactionChainOptionsType::Evm => Some(ChainOptions::EVM {
                chain_id: tco.chain_id,
            }),
            TransactionChainOptionsType::Btc => Some(ChainOptions::BTC {
                prev_scripts: tco.prev_scripts,
                input_amounts: tco.input_amounts,
            }),
            TransactionChainOptionsType::Substrate => Some(ChainOptions::SUBSTRATE {
                call: tco.call,
                era: tco.era,
                nonce: tco.nonce,
                tip: tco.tip,
                asset_id: tco.asset_id,
                block_hash: tco.block_hash,
                genesis_hash: tco.genesis_hash,
                spec_version: tco.spec_version,
                transaction_version: tco.transaction_version,
                app_id: tco.app_id,
                signed_extensions: tco.signed_extensions,
            }),
            TransactionChainOptionsType::Cosmos => Some(ChainOptions::COSMOS {
                chain_id: tco.cosmos_chain_id,
                account_number: tco.account_number,
            }),
        },
        None => None,
    }
}
