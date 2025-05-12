mod tip712;

use crate::protos::generated::trx::protocol;
use kos::chains::{ChainError, Transaction};
use kos::crypto::hash::{keccak256_digest, sha256_digest};
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

pub fn encode_sign_typed(message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
    if let Ok(data) = std::str::from_utf8(&message) {
        let digest = crate::chains::trx::tip712::hash_typed_data_json(data);

        return Ok(digest.unwrap().to_vec());
    }

    Err(ChainError::InvalidData("invalid typed data".to_string()))
}

pub fn encode_sign_message(message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
    let mut msg = Vec::new();
    msg.extend_from_slice(kos::chains::trx::TRON_MESSAGE_PREFIX.as_bytes());
    msg.extend_from_slice(message.len().to_string().as_bytes());
    msg.extend_from_slice(&message);

    Ok(keccak256_digest(&msg[..]).to_vec())
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

    #[test]
    fn test_encode_typed_data() {
        let data = r#"{
    "types": {
        "PermitTransfer": [
            {
                "name": "token",
                "type": "address"
            },
            {
                "name": "serviceProvider",
                "type": "address"
            },
            {
                "name": "user",
                "type": "address"
            },
            {
                "name": "receiver",
                "type": "address"
            },
            {
                "name": "value",
                "type": "uint256"
            },
            {
                "name": "maxFee",
                "type": "uint256"
            },
            {
                "name": "deadline",
                "type": "uint256"
            },
            {
                "name": "version",
                "type": "uint256"
            },
            {
                "name": "nonce",
                "type": "uint256"
            }
        ]
    },
    "primaryType": "PermitTransfer",
    "domain": {
        "name": "GasFreeController",
        "version": "V1.0.0",
        "chainId": 728126428,
        "verifyingContract": "TFFAMQLZybALaLb4uxHA9RBE7pxhUAjF3U"
    },
    "message": {
        "token": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "serviceProvider": "TLntW9Z59LYY5KEi9cmwk3PKjQga828ird",
        "user": "TCXs584P995owJmBifUZqNUUD6BSnBmvot",
        "receiver": "TGJSxpAWwaUoqT8sLFxX2TD7BP7MrpdwWo",
        "value": "1000000",
        "maxFee": "2000000",
        "deadline": "1746015449",
        "version": "1",
        "nonce": "1"
    }
}"#;

        let message = data.as_bytes();

        let signature = encode_sign_typed(message.to_vec()).unwrap();
        assert_eq!(
            hex::encode(signature),
            "a546b17147e14ec2aa418ca2eb7490bacaa60453cf902e292b01f02e02e83264"
        );
    }

    #[test]
    fn test_encode_sign_message() {
        let message_bytes = "test message".as_bytes().to_vec();

        let signature = crate::chains::trx::encode_sign_message(message_bytes).unwrap();

        assert_eq!(
            hex::encode(signature),
            "991bc803d1ebee72d48c8872e8f8a6275423b848b23d898fd47b94210f4c84fe"
        );
    }
}
