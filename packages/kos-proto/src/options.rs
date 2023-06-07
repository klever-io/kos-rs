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
