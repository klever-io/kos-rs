use std::collections;

use serde::{Deserialize, Serialize};
use serde_json;
use wasm_bindgen::prelude::*;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ResultAccount {
    pub data: DataAccount,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DataAccount {
    pub account: Account,
}

impl ToString for ResultAccount {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct Asset {
    pub asset_id: String,
    pub collection: String,
    pub asset_name: String,
    pub asset_type: u8,
    pub balance: u64,
    pub precision: u8,
    pub frozen_balance: u64,
    pub unfrozen_balance: u64,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(getter_with_clone)]
pub struct Account {
    // pub address: String,
    #[serde(rename = "Nonce")]
    pub nonce: Option<u64>,
    #[serde(rename = "Balance")]
    pub balance: Option<u64>,
    // pub frozen_balance: u64,
    #[serde(rename = "Allowance")]
    pub allowance: Option<u64>,
    #[wasm_bindgen(skip)]
    pub assets: Option<collections::HashMap<String, Asset>>,
}
