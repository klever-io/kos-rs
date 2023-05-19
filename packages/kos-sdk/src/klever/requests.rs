use super::{models, KLV};
use crate::utils::http_get;
use kos_types::error::Error;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
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
