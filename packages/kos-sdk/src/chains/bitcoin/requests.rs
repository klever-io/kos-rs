use super::transaction::{estimate_fee, UTXO};
use crate::utils;

use kos_types::{error::Error, number::BigNumber};
use std::ops::Add;

pub async fn fetch_utxos(
    node_url: &str,
    address: &str,
    confirmations: u64,
) -> Result<Vec<UTXO>, Error> {
    let url = format!("{}/api/v2/utxo/{}", node_url, address);
    let mut list: Vec<UTXO> = utils::http_get_auth::<Vec<UTXO>>(url)
        .await?
        .into_iter()
        .filter(|utxo| utxo.confirmations >= confirmations)
        .collect();

    list.sort_by_key(|a| a.amount());

    Ok(list)
}

// Fetch UTXOs and sum up the total amount.
pub async fn balance(
    node_url: &str,
    address: &str,
    confirmations: u64,
) -> Result<BigNumber, Error> {
    let unspent = fetch_utxos(node_url, address, confirmations)
        .await?
        .into_iter()
        .map(|utxo| BigNumber::from_string(&utxo.value).unwrap_or_default())
        .reduce(|a, b| a.add(b));

    Ok(unspent.unwrap_or_default())
}

// Fetch UTXOs from Bitcoin node and select UTXOs to cover the desired amount.
#[allow(clippy::too_many_arguments)]
pub async fn select_utxos(
    node_url: &str,
    address: &str,
    desired_amount: &BigNumber,
    outputs: u64,
    confirmations: u64,
    sats_per_bytes: u64,
    spend_biggest_first: bool,
    spend_all: bool,
) -> Result<Vec<UTXO>, Error> {
    let mut unspent: Vec<UTXO> = fetch_utxos(node_url, address, confirmations).await?;

    if spend_all {
        return Ok(unspent);
    }

    // min TX Value defined by dust
    let min_value = BigNumber::from(148 * sats_per_bytes);

    let tx_fee_min = estimate_fee(1, outputs, sats_per_bytes).add(desired_amount.clone());
    let tx_fee_max = estimate_fee(1, outputs + 1, sats_per_bytes).add(desired_amount.clone());

    // check if there is a UTXO that better match the desired amount
    for utxo in &unspent {
        let value = utxo.amount();

        // if utxo match the desired amount, stop selecting UTXOs.
        // todo!("revisit this logic")
        if value.ge(&tx_fee_min) && value.le(&tx_fee_max) {
            return Ok(vec![utxo.clone()]);
        }
    }

    // accumulate UTXOs until we have enough value
    // reverse order to reduce the number of UTXOs
    if spend_biggest_first {
        unspent.sort_by_key(|b| std::cmp::Reverse(b.amount()))
    }

    // Vector to hold selected UTXOs.
    let mut selected_utxos = Vec::new();
    // Variable to keep track of the total amount in the selected UTXOs.
    let mut total_amount = BigNumber::from(0);

    for utxo in unspent {
        let value = BigNumber::from_string(&utxo.value)?;

        // Ignore dust values
        if value.lt(&min_value) {
            continue;
        }

        // Add the value of the UTXO to the total amount.
        total_amount = total_amount.add(value);

        // Add the UTXO to the selected UTXOs.
        selected_utxos.push(utxo);

        // if we have select utxos with enough value, stop looping (but keep processing utxos for a better match)
        if total_amount.ge(&tx_fee_min) {
            break;
        }
    }

    Ok(selected_utxos)
}

// Broadcast raw hex transaction to Bitcoin node.
pub async fn broadcast(node_url: &str, hex_tx: &str) -> Result<String, Error> {
    let url = format!("{}/api/v2/sendtx/", node_url);
    let data = hex_tx.as_bytes().to_vec();

    let result = utils::http_post_auth::<serde_json::Value>(url, &data).await;

    let result = result?;

    if let Some(err) = result.get("error") {
        if let Some(err) = err.as_str() {
            return Err(Error::ReqwestError(err.to_string()));
        }
    }

    if let Some(txid_value) = result.get("result") {
        if let Some(txid) = txid_value.as_str() {
            return Ok(txid.to_string());
        } else {
            return Err(Error::ReqwestError("txid is not a string".to_string()));
        }
    }

    Err(Error::ReqwestError("missing txid".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_utxos() {
        let node = &crate::utils::get_node_url("BTC");

        let amount = BigNumber::from_string("20000000").unwrap();
        let list = tokio_test::block_on(select_utxos(
            node,
            "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
            &amount,
            0,
            0,
            10,
            false,
            false,
        ))
        .unwrap();

        // computer total
        let total = list
            .iter()
            .map(|utxo| BigNumber::from_string(&utxo.value).unwrap_or_default())
            .reduce(|a, b| a.add(b))
            .unwrap_or_default();

        println!("total: {:?}", total);

        assert!(total.ge(&amount));
    }

    #[test]
    fn test_spend_all() {
        let node = &crate::utils::get_node_url("BTC");

        let selected = tokio_test::block_on(select_utxos(
            node,
            "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
            &BigNumber::from(0),
            0,
            0,
            10,
            false,
            true,
        ))
        .unwrap();

        // get all utxos
        let list = tokio_test::block_on(fetch_utxos(
            "https://bitcoin.explorer.klever.io",
            "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
            0,
        ))
        .unwrap();

        assert_eq!(selected.len(), list.len());
    }
}
