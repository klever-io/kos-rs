use crate::utils;
use kos_types::error::Error;
use serde_json::json;

use serde::Serialize;

#[derive(Serialize)]
pub struct TransferOptions {
    #[serde(flatten)]
    pub contract: kos_proto::tron::TriggerSmartContract,
    pub fee_limit: u32,
}

pub async fn get_account(node_url: &str, address: &str) -> Result<kos_proto::tron::Account, Error> {
    let url = format!("{}/wallet/getaccount", node_url);

    let data = json!({ "address": address }).to_string().into_bytes();

    let mut r: serde_json::Value = utils::http_post::<serde_json::Value>(url, &data).await?;

    // remove hash map for now todo!(): fix this
    let v = r.as_object_mut().unwrap();
    for key in [
        "assetV2",
        "asset",
        "free_asset_net_usage",
        "free_asset_net_usageV2",
    ]
    .into_iter()
    {
        v.remove(key);
    }

    let acc: kos_proto::tron::Account = serde_json::from_str(&r.to_string())?;

    Ok(acc)
}

pub async fn broadcast(
    node_url: &str,
    tx: kos_proto::tron::Transaction,
) -> Result<serde_json::Value, Error> {
    let url = format!("{}/wallet/broadcasthex", node_url);

    log::debug!(
        "Broadcasting to {}\nData: {} ",
        url,
        serde_json::to_string(&tx)?,
    );

    // hex encode tx data
    let tx_raw = kos_proto::write_message(&tx);

    // adjust to tron format
    let data = format!("{{\"transaction\": \"{}\"}}", hex::encode(tx_raw),);

    utils::http_post::<serde_json::Value>(url, data.as_bytes()).await
}

pub async fn create_transfer(
    node_url: &str,
    contract: kos_proto::tron::TransferContract,
) -> Result<kos_proto::tron::Transaction, Error> {
    let url = format!("{}/wallet/createtransaction", node_url);

    create_transaction(url, contract).await
}

pub async fn create_asset_transfer(
    node_url: &str,
    contract: kos_proto::tron::TransferAssetContract,
) -> Result<kos_proto::tron::Transaction, Error> {
    let url = format!("{}/wallet/transferasset", node_url);

    create_transaction(url, contract).await
}

pub async fn create_trc20_transfer(
    node_url: &str,
    contract: TransferOptions,
) -> Result<kos_proto::tron::Transaction, Error> {
    let url = format!("{}/wallet/triggersmartcontract", node_url);

    create_transaction(url, contract).await
}

async fn create_transaction(
    url: String,
    contract: impl serde::Serialize,
) -> Result<kos_proto::tron::Transaction, Error> {
    let data = serde_json::to_string(&contract)?.as_bytes().to_vec();
    let result = utils::http_post::<serde_json::Value>(url, &data).await?;
    let raw_hex = unpack_result(result)?;
    pack_tx(&raw_hex)
}

fn pack_tx(raw_hex: &str) -> Result<kos_proto::tron::Transaction, Error> {
    // encode raw data
    let raw_data_bytes = hex::decode(raw_hex)?;
    let raw_data: kos_proto::tron::transaction::Raw = kos_proto::from_bytes(raw_data_bytes)
        .map_err(|e| Error::InvalidTransaction(e.to_string()))?;

    Ok(kos_proto::tron::Transaction {
        raw_data: Some(raw_data),
        signature: Vec::new(),
        ret: Vec::new(),
    })
}

fn unpack_result(value: serde_json::Value) -> Result<String, Error> {
    if let Some(v) = value.get("raw_data_hex").and_then(|v| v.as_str()) {
        return Ok(v.to_string());
    }

    if let Some(transaction) = value.get("transaction") {
        if let Some(v) = transaction.get("raw_data_hex").and_then(|v| v.as_str()) {
            return Ok(v.to_string());
        }
    }

    match value.get("Error") {
        Some(err) => Err(Error::ReqwestError(err.to_string())),
        None => Err(Error::ReqwestError("Unknown error".to_string())),
    }
}
