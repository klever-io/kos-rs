use crate::utils;
use kos_types::error::Error;
use serde_json::json;

pub async fn get_account(node_url: &str, address: &str) -> Result<kos_proto::tron::Account, Error> {
    let url = format!("{}/wallet/getaccount", node_url);

    let data = json!({ "address": address }).to_string().into_bytes();

    let r: serde_json::Value = utils::http_post::<serde_json::Value>(url, &data).await?;
    let acc: kos_proto::tron::Account = serde_json::from_str(&r.to_string())?;

    Ok(acc)
}
