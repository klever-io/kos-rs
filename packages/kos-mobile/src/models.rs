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
