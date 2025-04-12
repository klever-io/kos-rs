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

        assert_eq!(hex::encode(result.raw_data), "7b22426c6f636b223a6e756c6c2c2252617744617461223a7b2242616e647769647468466565223a313030303030302c22436861696e4944223a224d5441774e444977222c22436f6e7472616374223a5b7b22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6e7472616374222c2276616c7565223a224369417973796730416a38786a2f72723558475536694a2b41544932396d6e52485330573042724331767a304342674b227d2c2254797065223a6e756c6c7d5d2c2244617461223a6e756c6c2c224b417070466565223a3530303030302c224b4441466565223a6e756c6c2c224e6f6e6365223a33392c225065726d697373696f6e4944223a6e756c6c2c2253656e646572223a22354273794f6c6366325658676e4e5157595039455a6350305270504966792b75704b44385149636e794f6f3d222c2256657273696f6e223a317d2c225265636569707473223a6e756c6c2c22526573756c74223a6e756c6c2c22526573756c74436f6465223a6e756c6c2c225369676e6174757265223a5b2241674141414567414141417752534942435a59724b4464506f39476741304d772f6e644671774c62423830335a456e6d54573574225d7d");
        assert_eq!(
            hex::encode(result.signature),
            "02000000480000003045220109962b28374fa3d1a0034330fe7745ab02db07cd376449e64d6e6d"
        );
    }
}
