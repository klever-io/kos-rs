use kos::chains::{ChainError, Transaction};

pub fn encode_for_sign(transaction: Transaction) -> Result<Transaction, ChainError> {
    Ok(transaction)
}
