use kos_types::error::Error;

use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections,
    fmt::{self, Display, Formatter},
};
use wasm_bindgen::prelude::*;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ResultAccount {
    pub data: DataAccount,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DataAccount {
    pub account: Account,
}

impl std::fmt::Display for ResultAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(&self) {
            Ok(json_str) => write!(f, "({})", json_str),
            Err(e) => write!(f, "{}", e),
        }
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

pub struct TransactionResult {
    pub tx_hash: String,
    pub tx: kos_proto::klever::Transaction,
}

impl TryFrom<serde_json::value::Value> for TransactionResult {
    type Error = kos_types::error::Error;

    fn try_from(value: serde_json::value::Value) -> Result<Self, Self::Error> {
        if let Some(v) = value.get("data") {
            if let Some(obj) = v.as_object() {
                let hash = obj.get("txHash").unwrap().as_str().unwrap();
                let result = obj.get("result").unwrap().to_string();
                let tx: kos_proto::klever::Transaction = serde_json::from_str(&result)?;
                return Ok(Self {
                    tx_hash: hash.to_string(),
                    tx,
                });
            }
        }

        match value.get("error") {
            Some(err) => Err(Error::ReqwestError(err.to_string())),
            None => Err(Error::ReqwestError("Unknown error".to_string())),
        }
    }
}

// SendTXRequest -
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SendTXRequest {
    #[serde(rename = "type")]
    pub tx_type: u32,
    #[serde(rename = "sender")]
    pub sender: String,
    #[serde(rename = "nonce")]
    pub nonce: Option<u64>,
    #[serde(rename = "permID")]
    pub perm_id: Option<i32>,
    #[serde(rename = "data")]
    pub data: Option<Vec<Vec<u8>>>,
    #[serde(rename = "contract")]
    pub contract: Option<serde_json::Value>,
    #[serde(rename = "contracts")]
    pub contracts: Option<Vec<serde_json::Value>>,
    #[serde(rename = "kdaFee")]
    pub kda_fee: Option<String>,
}

impl SendTXRequest {
    pub fn set_contract(&mut self, contract: impl Serialize) -> Result<(), Error> {
        let data = serde_json::to_value(&contract)?;
        self.contract = Some(data);
        Ok(())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let data = serde_json::to_vec(&self).map_err(Error::from)?;
        Ok(data)
    }
}

impl Display for SendTXRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
// TransferTXRequest -
pub struct TransferTXRequest {
    #[serde(rename = "receiver")]
    pub receiver: String,
    #[serde(rename = "amount")]
    pub amount: i64,
    #[serde(rename = "kda")]
    pub kda: Option<String>,
    #[serde(rename = "kdaRoyalties")]
    pub kda_royalties: Option<i64>,
}

impl std::fmt::Display for TransferTXRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(&self) {
            Ok(json_str) => write!(f, "({})", json_str),
            Err(e) => write!(f, "{}", e),
        }
    }
}
