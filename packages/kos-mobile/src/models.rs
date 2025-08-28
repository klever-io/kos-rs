use kos::chains::util::hex_string_to_vec;
use kos::chains::{ChainOptions, CustomChainType};
use kos::crypto::base64;

#[derive(uniffi::Enum)]
pub enum TransactionChainOptions {
    Evm {
        chain_id: u32,
    },
    Btc {
        prev_scripts: Vec<Vec<u8>>,
        input_amounts: Vec<u64>,
    },
    Substrate {
        call: Vec<u8>,
        era: Vec<u8>,
        nonce: u32,
        tip: u64,
        block_hash: Vec<u8>,
        genesis_hash: Vec<u8>,
        spec_version: u32,
        transaction_version: u32,
        app_id: Option<u32>,
    },
    Cosmos {
        chain_id: String,
        account_number: u64,
    },
}

#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn new_substrate_transaction_options(
    call: String,
    era: String,
    nonce: u32,
    tip: u64,
    block_hash: String,
    genesis_hash: String,
    spec_version: u32,
    transaction_version: u32,
    app_id: Option<u32>,
) -> TransactionChainOptions {
    let call = hex_string_to_vec(call.as_str()).unwrap_or_default();
    let era = hex_string_to_vec(era.as_str()).unwrap_or_default();
    let block_hash = hex_string_to_vec(block_hash.as_str()).unwrap_or_default();
    let genesis_hash = hex_string_to_vec(genesis_hash.as_str()).unwrap_or_default();

    TransactionChainOptions::Substrate {
        call,
        era,
        nonce,
        tip,
        block_hash,
        genesis_hash,
        spec_version,
        transaction_version,
        app_id,
    }
}

#[uniffi::export]
pub fn new_bitcoin_transaction_options(
    input_amounts: Vec<u64>,
    prev_scripts: Vec<String>,
) -> TransactionChainOptions {
    let prev_scripts = prev_scripts
        .iter()
        .map(|s| base64::simple_base64_decode(s).unwrap_or_default())
        .collect();

    TransactionChainOptions::Btc {
        prev_scripts,
        input_amounts,
    }
}

#[uniffi::export]
pub fn new_evm_transaction_options(chain_id: u32) -> TransactionChainOptions {
    TransactionChainOptions::Evm { chain_id }
}

#[uniffi::export]
pub fn new_cosmos_transaction_options(
    chain_id: String,
    account_number: u64,
) -> TransactionChainOptions {
    TransactionChainOptions::Cosmos {
        chain_id,
        account_number,
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum WalletChainOptions {
    CustomEth { chain_id: u32 },
    CustomIcp { key_type: String }, // "ed25519" or "secp256k1"
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct WalletOptions {
    pub use_legacy_path: bool,
    pub specific: Option<WalletChainOptions>,
}

#[uniffi::export]
pub fn new_wallet_options(use_legacy_path: bool) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: None,
    }
}

#[uniffi::export]
pub fn new_eth_wallet_options(use_legacy_path: bool, chain_id: u32) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: Some(WalletChainOptions::CustomEth { chain_id }),
    }
}

#[uniffi::export]
pub fn new_icp_wallet_options(use_legacy_path: bool, key_type: String) -> WalletOptions {
    WalletOptions {
        use_legacy_path,
        specific: Some(WalletChainOptions::CustomIcp { key_type }),
    }
}

// Helper function to convert wallet options to CustomChainType
pub fn wallet_options_to_chain_type(
    chain_id: u32,
    options: &Option<WalletOptions>,
) -> CustomChainType {
    match options {
        Some(opts) => match &opts.specific {
            Some(WalletChainOptions::CustomEth {
                chain_id: custom_chain_id,
            }) => CustomChainType::CustomEth(*custom_chain_id),
            Some(WalletChainOptions::CustomIcp { key_type }) => {
                CustomChainType::CustomIcp(key_type.clone())
            }
            None => CustomChainType::NotCustomBase(chain_id),
        },
        None => CustomChainType::NotCustomBase(chain_id),
    }
}

// Helper function to convert TransactionChainOptions to ChainOptions
pub fn convert_tx_options(options: Option<TransactionChainOptions>) -> Option<ChainOptions> {
    match options {
        Some(TransactionChainOptions::Evm { chain_id }) => Some(ChainOptions::EVM { chain_id }),
        Some(TransactionChainOptions::Btc {
            prev_scripts,
            input_amounts,
        }) => Some(ChainOptions::BTC {
            prev_scripts,
            input_amounts,
        }),
        Some(TransactionChainOptions::Substrate {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        }) => Some(ChainOptions::SUBSTRATE {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        }),
        Some(TransactionChainOptions::Cosmos {
            chain_id,
            account_number,
        }) => Some(ChainOptions::COSMOS {
            chain_id,
            account_number,
        }),
        None => None,
    }
}
