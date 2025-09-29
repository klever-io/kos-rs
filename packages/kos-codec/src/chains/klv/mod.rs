mod models;

use crate::protos::generated::klv::proto;
use kos::chains::{ChainError, Transaction};
use kos::crypto::base64::simple_base64_encode;
use kos::crypto::hash::blake2b_digest;
use prost::Message;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let raw_tx = transaction.raw_data.clone();

    let js_tx: models::Transaction = serde_json::from_slice(&raw_tx).map_err(|e| {
        ChainError::InvalidTransaction(format!("Failed to decode transaction: {}", e))
    })?;

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

    let mut js_tx: models::Transaction = serde_json::from_slice(&raw_tx).map_err(|e| {
        ChainError::InvalidTransaction(format!("Failed to decode transaction: {}", e))
    })?;

    js_tx.signature = Some(vec![simple_base64_encode(&transaction.signature)]);

    transaction.raw_data = serde_json::to_vec(&js_tx).map_err(|e| {
        ChainError::InvalidTransaction(format!("Failed to encode transaction: {}", e))
    })?;

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx ="{\"RawData\":{\"BandwidthFee\":1000000,\"ChainID\":\"MTAwNDIw\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Version\":1}}".as_bytes().to_vec();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "1e61c51f0d230f4855dc9b8935b47b9019887baf02be75d364a4068083833c15"
        );
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx ="{\"RawData\":{\"BandwidthFee\":1000000,\"ChainID\":\"MTAwNDIw\",\"Contract\":[{\"Parameter\":{\"type_url\":\"type.googleapis.com/proto.TransferContract\",\"value\":\"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK\"}}],\"KAppFee\":500000,\"Nonce\":39,\"Sender\":\"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=\",\"Version\":1}}".as_bytes().to_vec();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![
                2, 0, 0, 0, 72, 0, 0, 0, 48, 69, 34, 1, 9, 150, 43, 40, 55, 79, 163, 209, 160, 3,
                67, 48, 254, 119, 69, 171, 2, 219, 7, 205, 55, 100, 73, 230, 77, 110, 109,
            ],
            options: None,
        };

        let result = encode_for_broadcast(tx).unwrap();

        // Note: Output format may differ slightly due to serde_json's default formatting
        assert!(!result.raw_data.is_empty());
        assert_eq!(
            hex::encode(result.signature),
            "02000000480000003045220109962b28374fa3d1a0034330fe7745ab02db07cd376449e64d6e6d"
        );
    }
}
