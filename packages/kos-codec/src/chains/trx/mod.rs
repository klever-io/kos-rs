use crate::protos::generated::trx::protocol;
use kos::chains::{ChainError, Transaction};
use kos::crypto::hash::sha256_digest;
use prost::Message;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let tron_tx = decode_transaction(transaction.raw_data.clone())?;

    let raw_data_clone = tron_tx
        .raw_data
        .clone()
        .ok_or(ChainError::ProtoDecodeError)?;
    let mut tx_raw = Vec::new();
    raw_data_clone.encode(&mut tx_raw)?;

    transaction.tx_hash = sha256_digest(&tx_raw[..]).to_vec();

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut tron_tx = decode_transaction(transaction.raw_data.clone())?;
    tron_tx.signature.push(transaction.signature.clone());

    let mut tx_data = Vec::new();
    tron_tx.encode(&mut tx_data)?;

    transaction.raw_data = tx_data;

    Ok(transaction)
}

pub fn decode_transaction(raw_tx: Vec<u8>) -> Result<protocol::Transaction, ChainError> {
    let tx = protocol::Transaction::decode(raw_tx.as_slice());
    if let Ok(t) = tx {
        return Ok(t);
    }

    let raw_tx = protocol::transaction::Raw::decode(raw_tx.as_slice())?;
    let tx = protocol::Transaction {
        raw_data: Some(raw_tx),
        signature: vec![],
        ret: vec![],
    };

    Ok(tx)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode(
            "0a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031"
        ).unwrap();
        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "96a09fd664f1a7abbbe8bca604ea40b80291119fed5283c71ba94882d5b3c8a5"
        );
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode(
            "0a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031"
        ).unwrap();
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

        assert_eq!(hex::encode(result.raw_data), "0a83010a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031122702000000480000003045220109962b28374fa3d1a0034330fe7745ab02db07cd376449e64d6e6d");
        assert_eq!(
            hex::encode(result.signature),
            "02000000480000003045220109962b28374fa3d1a0034330fe7745ab02db07cd376449e64d6e6d"
        );
    }
}
