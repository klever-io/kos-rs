mod models;

use crate::chains::eth::models::EthereumTransaction;
use kos::chains::{ChainError, Transaction};
use kos::crypto::hash::keccak256_digest;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut eth_tx = EthereumTransaction::decode(&transaction.raw_data)?;

    let new_rlp = eth_tx.encode()?;
    let to_sign = keccak256_digest(&new_rlp[..]);

    transaction.tx_hash = to_sign.to_vec();
    Ok(transaction)
}

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    public_key: String,
) -> Result<Transaction, ChainError> {
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
