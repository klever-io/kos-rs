mod chains;

use crate::chains::ada;
use kos::chains::{get_chain_by_base_id, Chain, ChainError, ChainType, Transaction};

pub fn encode_for_signing(
    chain_id: u32,
    transaction: Transaction,
) -> Result<Transaction, ChainError> {
    let chain = match get_chain_by_base_id(chain_id) {
        Some(chain) => chain,
        None => return Err(ChainError::UnsupportedChain),
    };

    Ok(match chain.get_chain_type() {
        ChainType::ADA => ada::encode_for_sign(transaction)?,
        _ => transaction,
    })
}

pub fn encode_for_broadcast(
    chain_id: u32,
    transaction: Transaction,
    public_key: Vec<u8>,
) -> Result<Transaction, ChainError> {
    let chain = match get_chain_by_base_id(chain_id) {
        Some(chain) => chain,
        None => return Err(ChainError::UnsupportedChain),
    };

    Ok(match chain.get_chain_type() {
        ChainType::ADA => ada::encode_for_broadcast(transaction, public_key)?,
        _ => transaction,
    })
}
