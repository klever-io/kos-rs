use super::models;
use crate::{chain, models::TransactionRaw, utils};
use kos_types::{error::Error, hash::Hash};
use serde::Serialize;

pub async fn get_account(node_url: &str, address: &str) -> Result<models::Account, Error> {
    let url = format!("{}/address/{}", node_url, address);

    utils::http_get::<models::ResultAccount>(url)
        .await
        .map(|r| r.data.account)
}

pub async fn broadcast(
    node_url: &str,
    tx: kos_proto::klever::Transaction,
) -> Result<serde_json::Value, Error> {
    let url = format!("{}/transaction/broadcast", node_url);
    log::debug!(
        "Broadcasting to {}\nData: {} ",
        url,
        serde_json::to_string(&tx)?,
    );

    // adjust to kleverchain format
    let data = format!(
        "{{\"tx\": {}}}",
        serde_json::to_string(&tx)?.replace("typeUrl", "type_url"),
    )
    .as_bytes()
    .to_vec();

    utils::http_post::<serde_json::Value>(url, &data).await
}

pub async fn send_request(
    node_url: &str,
    request: &mut models::SendTXRequest,
) -> Result<serde_json::Value, Error> {
    let url = format!("{}/transaction/send", node_url);

    if request.nonce.unwrap_or(0) == 0 {
        let account = get_account(node_url, &request.sender).await?;
        request.nonce = account.nonce;
    }

    log::debug!("Send request: {}", request.to_string());

    // to json
    let data = request.to_vec().unwrap();

    utils::http_post::<serde_json::Value>(url, &data).await
}

pub async fn make_request(
    sender: String,
    contract: impl Serialize,
    options: &kos_proto::options::KLVOptions,
    node: &str,
) -> Result<crate::models::Transaction, Error> {
    let mut tx_request = models::SendTXRequest {
        tx_type: 0,
        sender: sender.to_owned(),
        nonce: options.nonce,
        perm_id: None,
        data: None,
        contract: None,
        contracts: None,
        kda_fee: None,
    };

    tx_request.set_contract(contract)?;
    let result = send_request(node, &mut tx_request).await?;
    let tx = models::TransactionResult::try_from(result)?;

    Ok(crate::models::Transaction {
        chain: chain::Chain::KLV,
        sender: sender,
        hash: Hash::new(&tx.tx_hash)?,
        data: Some(TransactionRaw::Klever(tx.tx)),
    })
}
