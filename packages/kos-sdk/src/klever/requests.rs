use super::{models, KLV};
use crate::utils::{http_get, http_post};
use kos_types::error::Error;

pub async fn get_account(
    node_url: Option<String>,
    address: &str,
) -> Result<models::Account, Error> {
    let url = format!(
        "{}/address/{}",
        node_url.unwrap_or_else(|| KLV::base_chain().node_url.to_string()),
        address,
    );

    http_get::<models::ResultAccount>(url)
        .await
        .map(|r| r.data.account)
}

pub async fn broadcast(
    node_url: Option<String>,
    data: &Vec<u8>,
) -> Result<serde_json::Value, Error> {
    let url = format!(
        "{}/transaction/broadcast",
        node_url.unwrap_or_else(|| KLV::base_chain().node_url.to_string()),
    );

    http_post::<serde_json::Value>(url, data).await
}
