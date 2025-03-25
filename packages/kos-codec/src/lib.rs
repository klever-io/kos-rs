mod chains;

use crate::chains::ada;
use crate::chains::xrp;
use kos::chains::{get_chain_by_base_id, ChainError, ChainType, Transaction};

#[derive(Clone)]
pub struct KosCodedAccount {
    pub chain_id: u32,
    pub address: String,
    pub public_key: String,
}

pub fn encode_for_signing(
    account: KosCodedAccount,
    transaction: Transaction,
) -> Result<Transaction, ChainError> {
    let chain = match get_chain_by_base_id(account.chain_id) {
        Some(chain) => chain,
        None => return Err(ChainError::UnsupportedChain),
    };

    Ok(match chain.get_chain_type() {
        ChainType::XRP => xrp::encode_for_sign(transaction, account.public_key)?,
        ChainType::ADA => ada::encode_for_sign(transaction)?,
        _ => transaction,
    })
}

pub fn encode_for_broadcast(
    account: KosCodedAccount,
    transaction: Transaction,
) -> Result<Transaction, ChainError> {
    let chain = match get_chain_by_base_id(account.chain_id) {
        Some(chain) => chain,
        None => return Err(ChainError::UnsupportedChain),
    };

    Ok(match chain.get_chain_type() {
        ChainType::XRP => xrp::encode_for_broadcast(transaction)?,
        ChainType::ADA => ada::encode_for_broadcast(transaction, account)?,
        _ => transaction,
    })
}
