use kos::chains::{ChainError, Transaction};

pub fn encode_for_sign(transaction: Transaction) -> Result<Transaction, ChainError> {
    Ok(transaction)
}

pub fn encode_for_broadcast(transaction: Transaction) -> Result<Transaction, ChainError> {
    Ok(transaction)
}
