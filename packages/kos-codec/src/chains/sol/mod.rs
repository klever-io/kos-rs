use crate::chains::sol::models::SolanaTransaction;
use kos::chains::{ChainError, Transaction};

mod models;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut sol_tx = SolanaTransaction::decode(&transaction.raw_data)?;

    if sol_tx.message.header.num_required_signatures as usize != 1 {
        return Err(ChainError::InvalidTransactionHeader);
    }
    if sol_tx.message.account_keys.is_empty() {
        return Err(ChainError::InvalidAccountLength);
    }
    if sol_tx.message.recent_blockhash.iter().all(|&x| x == 0)
        || sol_tx.message.recent_blockhash.iter().all(|&x| x == 1)
    {
        return Err(ChainError::InvalidBlockhash);
    }

    transaction.tx_hash = sol_tx.message.encode()?;

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut sol_tx = SolanaTransaction::decode(&transaction.raw_data)?;

    if transaction.signature.len() != 64 {
        return Err(ChainError::InvalidSignatureLength);
    }
    sol_tx.signatures = vec![transaction.signature.clone()];

    transaction.tx_hash = sol_tx.signatures[0].clone();

    let signed_tx = sol_tx.encode()?;

    transaction.raw_data = signed_tx;
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
