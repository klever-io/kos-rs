use crate::protos::generated::trx::protocol;
use kos::chains::{ChainError, Transaction};
use kos::crypto::hash::sha256_digest;
use prost::Message;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut tron_tx = decode_transaction(transaction.raw_data.clone())?;

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
    match tx {
        Ok(t) => return Ok(t),
        Err(_) => {}
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
    fn test_encode_for_sign() {}

    #[test]
    fn test_encode_for_broadcast() {}
}
