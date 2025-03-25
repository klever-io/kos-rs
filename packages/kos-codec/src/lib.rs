mod chains;

use crate::chains::ada;
use crate::chains::atom;
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
        ChainType::ETH => transaction,
        ChainType::BTC => transaction,
        ChainType::TRX => transaction,
        ChainType::KLV => transaction,
        ChainType::SUBSTRATE => transaction,
        ChainType::XRP => xrp::encode_for_sign(transaction, account.public_key)?,
        ChainType::ICP => transaction,
        ChainType::SOL => transaction,
        ChainType::ADA => ada::encode_for_sign(transaction)?,
        ChainType::SUI => transaction,
        ChainType::APT => transaction,
        ChainType::ATOM => atom::encode_for_sign(transaction)?,
        ChainType::BCH => transaction,
        ChainType::BNB => transaction,
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
        ChainType::ETH => transaction,
        ChainType::BTC => transaction,
        ChainType::TRX => transaction,
        ChainType::KLV => transaction,
        ChainType::SUBSTRATE => transaction,
        ChainType::XRP => xrp::encode_for_broadcast(transaction)?,
        ChainType::ICP => transaction,
        ChainType::SOL => transaction,
        ChainType::ADA => ada::encode_for_broadcast(transaction)?,
        ChainType::SUI => transaction,
        ChainType::APT => transaction,
        ChainType::ATOM => atom::encode_for_broadcast(transaction)?,
        ChainType::BCH => transaction,
        ChainType::BNB => transaction,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode() {
        let tx = Transaction {
            raw_data: vec![],
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let account = KosCodedAccount {
            chain_id: 20,
            address: "123".to_string(),
            public_key: "123".to_string(),
        };

        let result = encode_for_signing(account, tx);

        assert!(result.is_ok());
    }
}
