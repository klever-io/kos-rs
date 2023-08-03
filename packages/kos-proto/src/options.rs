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
        self.dust_value
            .clone()
            .unwrap_or_else(|| BigNumber::from(546))
    }
    pub fn sats_per_bytes(&self) -> u64 {
        self.sats_per_bytes.clone().unwrap_or_else(|| 1)
    }
    pub fn receivers(&self) -> Vec<(String, BigNumber)> {
        self.receivers.clone().unwrap_or_else(|| Vec::new())
    }

    pub fn rbf(&self) -> bool {
        self.rbf.clone().unwrap_or_else(|| false)
    }
}
