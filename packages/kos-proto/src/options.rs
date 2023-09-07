use kos_types::number::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
pub struct KLVOptions {
    pub nonce: Option<u64>,
    pub kda: Option<String>,
    pub kda_royalties: Option<i64>,
    pub memo: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TRXOptions {
    pub token: Option<String>,
    pub fee_limit: Option<i64>,
    pub memo: Option<String>,
}

impl Default for TRXOptions {
    fn default() -> Self {
        Self {
            token: None,
            fee_limit: Some(10_000_000),
            memo: None,
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

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct BTCOptions {
    /// hex magic from network (default is bitcoin mainnet)
    pub network: Option<String>,
    pub sats_per_bytes: Option<u64>,
    pub dust_value: Option<BigNumber>,
    pub send_all: Option<bool>,
    pub change_address: Option<String>,
    pub receivers: Option<Vec<(String, BigNumber)>>,
    pub rbf: Option<bool>,
}

impl BTCOptions {
    pub fn dust_value(&self) -> BigNumber {
        self.dust_value.clone().unwrap_or(BigNumber::from(546))
    }
    pub fn sats_per_bytes(&self) -> u64 {
        self.sats_per_bytes.unwrap_or(1)
    }
    pub fn receivers(&self) -> Vec<(String, BigNumber)> {
        self.receivers.clone().unwrap_or_default()
    }

    pub fn rbf(&self) -> bool {
        self.rbf.unwrap_or(false)
    }
}
