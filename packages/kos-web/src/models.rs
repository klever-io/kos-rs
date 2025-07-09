use crate::error::Error;
use kos::chains::util::hex_string_to_vec;
use kos::chains::{ChainOptions, CustomChainType};
use kos::crypto::base64;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
#[wasm_bindgen]
pub struct PathOptions {
    #[wasm_bindgen(skip)]
    pub index: u32,
    #[wasm_bindgen(skip)]
    pub is_legacy: Option<bool>,
}

#[wasm_bindgen]
impl PathOptions {
    #[wasm_bindgen(constructor)]
    pub fn constructor() -> Self {
        Self::default()
    }

    pub fn new(index: u32) -> Self {
        Self {
            index,
            is_legacy: Some(false),
        }
    }
    #[wasm_bindgen(js_name = setIndex)]
    pub fn set_index(&mut self, index: u32) {
        self.index = index;
    }
    #[wasm_bindgen(js_name = setLegacy)]
    pub fn set_legacy(&mut self, is_legacy: bool) {
        self.is_legacy = Some(is_legacy);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Transaction {
    #[wasm_bindgen(skip)]
    pub raw_data: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub tx_hash: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub signature: Vec<u8>,
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(js_name = getRawData)]
    pub fn get_raw_data(&self) -> Vec<u8> {
        self.raw_data.clone()
    }

    #[wasm_bindgen(js_name = getTxHash)]
    pub fn get_tx_hash(&self) -> Vec<u8> {
        self.tx_hash.clone()
    }

    #[wasm_bindgen(js_name = getSignature)]
    pub fn get_signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WalletChainOptions {
    #[wasm_bindgen(skip)]
    #[serde(skip_serializing, skip_deserializing)]
    pub data: CustomChainType,
}

#[wasm_bindgen]
impl WalletChainOptions {
    #[wasm_bindgen(js_name = "newCustomEth")]
    pub fn new_custom_eth(chain_id: u32) -> WalletChainOptions {
        WalletChainOptions {
            data: CustomChainType::CustomEth(chain_id),
        }
    }

    #[wasm_bindgen(js_name = "newCustomIcp")]
    pub fn new_custom_icp(key_type: String) -> WalletChainOptions {
        WalletChainOptions {
            data: CustomChainType::CustomIcp(key_type),
        }
    }
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
            .map_err(|e| Error::WalletManager(format!("Invalid call hex: {e}")))?;
        let era = hex_string_to_vec(era.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid era hex: {e}")))?;
        let block_hash = hex_string_to_vec(block_hash.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid block hash hex: {e}")))?;
        let genesis_hash = hex_string_to_vec(genesis_hash.as_str())
            .map_err(|e| Error::WalletManager(format!("Invalid genesis hash hex: {e}")))?;

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

    #[wasm_bindgen(js_name = "newCosmosSignOptions")]
    pub fn new_cosmos_sign_options(
        chain_id: String,
        account_number: u64,
    ) -> TransactionChainOptions {
        TransactionChainOptions {
            data: {
                ChainOptions::COSMOS {
                    chain_id,
                    account_number,
                }
            },
        }
    }
}

// Helper function to convert wallet options to CustomChainType
pub fn wallet_options_to_chain_type(
    chain_id: u32,
    options: &Option<WalletChainOptions>,
) -> CustomChainType {
    if let Some(options) = options {
        return options.data.clone();
    }

    CustomChainType::NotCustomBase(chain_id)
}
