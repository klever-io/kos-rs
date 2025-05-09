mod chains;
mod protos;

use alloy_dyn_abi::TypedData;
use crate::chains::{ada, apt, atom, bch, btc, eth, icp, klv, sol, substrate, trx, xrp};
use kos::chains::{get_chain_by_base_id, ChainError, ChainType};

pub use kos::chains::{ChainOptions, Transaction};

#[derive(Clone, Debug)]
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
        ChainType::ATOM => atom::encode_for_sign(transaction)?,
        ChainType::BCH => bch::encode_for_sign(transaction)?,
        ChainType::BTC => btc::encode_for_sign(transaction)?,
        ChainType::KLV => klv::encode_for_sign(transaction)?,
        ChainType::TRX => trx::encode_for_sign(transaction)?,
        ChainType::SOL => sol::encode_for_sign(transaction)?,
        ChainType::ETH => eth::encode_for_sign(transaction)?,
        ChainType::SUBSTRATE => substrate::encode_for_sign(transaction, account)?,
        ChainType::ICP => icp::encode_for_sign(transaction)?,
        _ => transaction,
    })
}

pub fn encode_for_sign_message(
    account: KosCodedAccount,
    message: Vec<u8>,
) -> Result<Vec<u8>, ChainError> {
    let chain = match get_chain_by_base_id(account.chain_id) {
        Some(chain) => chain,
        None => return Err(ChainError::UnsupportedChain),
    };

    if let Ok(data) = std::str::from_utf8(&message) {
        if let Ok( mut typed_data) = serde_json::from_str::<TypedData>(data) {
            return Ok(match chain.get_chain_type() {
                ChainType::ETH => eth::encode_sign_typed(message)?,
                ChainType::TRX => trx::encode_sign_typed(message)?,
                _ => message,
            });
        }
    }

    Ok(match chain.get_chain_type() {
        ChainType::ETH => eth::encode_sign_message(message)?,
        ChainType::TRX => trx::encode_sign_message(message)?,
        _ => message,
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
        ChainType::ATOM => atom::encode_for_broadcast(transaction)?,
        ChainType::APT => apt::encode_for_broadcast(transaction, account)?,
        ChainType::BCH => bch::encode_for_broadcast(transaction, account.public_key)?,
        ChainType::BTC => btc::encode_for_broadcast(transaction, account.public_key)?,
        ChainType::KLV => klv::encode_for_broadcast(transaction)?,
        ChainType::TRX => trx::encode_for_broadcast(transaction)?,
        ChainType::SOL => sol::encode_for_broadcast(transaction)?,
        ChainType::ETH => eth::encode_for_broadcast(transaction)?,
        ChainType::SUBSTRATE => substrate::encode_for_broadcast(transaction, account)?,
        ChainType::ICP => icp::encode_for_broadcast(transaction)?,
        _ => transaction,
    })
}
