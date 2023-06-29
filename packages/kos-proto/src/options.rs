use kos_types::number::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct KLVOptions {
    pub nonce: Option<u64>,
    pub kda: Option<String>,
    pub kda_royalties: Option<i64>,
}

impl Default for KLVOptions {
    fn default() -> Self {
        Self {
            nonce: None,
            kda: None,
            kda_royalties: None,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TRXOptions {
    pub token: Option<String>,
    pub fee_limit: Option<i64>,
}

impl Default for TRXOptions {
    fn default() -> Self {
        Self {
            token: None,
            fee_limit: Some(10_000_000),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct ETHOptions {
    pub legacy_type: Option<bool>,
    pub nonce: Option<u64>,
    pub chain_id: Option<u64>,
    pub token: Option<String>,
    pub gas_limit: Option<BigNumber>,
    pub gas_price: Option<BigNumber>,
    pub contract_data: Option<Vec<u8>>,
    pub max_fee_per_gas: Option<BigNumber>,
    pub max_priority_fee_per_gas: Option<BigNumber>,
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct MATICOptions {
    pub eth: ETHOptions,
}
