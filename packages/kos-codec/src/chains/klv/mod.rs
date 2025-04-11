mod models;

use crate::protos::generated::klv::proto;
use kos::chains::{ChainError, Transaction};
use kos::crypto::base64::simple_base64_encode;
use kos::crypto::hash::blake2b_digest;
use prost::Message;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let raw_tx = transaction.raw_data.clone();

    // Parse [] empty arrays to [""] to avoid decoding errors
    let json = String::from_utf8(raw_tx.clone())?;
    let parsed = json.replace("[]", "[\"\"]").as_bytes().to_vec();

    let js_tx: models::Transaction = tiny_json_rs::decode(String::from_utf8(parsed)?)?;

    let klv_tx =
        proto::Transaction::try_from(js_tx.clone()).map_err(|_| ChainError::ProtoDecodeError)?;

    let raw_data = klv_tx
        .raw_data
        .clone()
        .ok_or(ChainError::ProtoDecodeError)?;
    let mut tx_raw = Vec::with_capacity(raw_data.encoded_len());
    raw_data.encode(&mut tx_raw)?;
    transaction.tx_hash = blake2b_digest(&tx_raw).to_vec();

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let raw_tx = transaction.raw_data.clone();

    // Parse [] empty arrays to [""] to avoid decoding errors
    let json = String::from_utf8(raw_tx.clone())?;
    let parsed = json.replace("[]", "[\"\"]").as_bytes().to_vec();

    let mut js_tx: models::Transaction = tiny_json_rs::decode(String::from_utf8(parsed)?)?;

    js_tx.signature = Some(Vec::from([simple_base64_encode(&transaction.signature)]));

    transaction.raw_data = tiny_json_rs::encode(js_tx).into_bytes();

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_for_sign() {}

    #[test]
    fn test_encode_for_broadcast() {}
}
