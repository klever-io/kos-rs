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
        ChainType::ETH => transaction,
        ChainType::BTC => transaction,
        ChainType::TRX => transaction,
        ChainType::KLV => transaction,
        ChainType::SUBSTRATE => transaction,
        ChainType::XRP => transaction,
        ChainType::ICP => transaction,
        ChainType::SOL => transaction,
        ChainType::ADA => ada::encode_for_sign(transaction)?,
        ChainType::SUI => transaction,
        ChainType::APT => transaction,
        ChainType::ATOM => transaction,
        ChainType::BCH => transaction,
        ChainType::BNB => transaction,
    })
}

pub fn encode_for_broadcast(
    chain: Box<dyn Chain>,
    transaction: Transaction,
) -> Result<Transaction, ChainError> {
    Ok(match chain.get_chain_type() {
        ChainType::ETH => transaction,
        ChainType::BTC => transaction,
        ChainType::TRX => transaction,
        ChainType::KLV => transaction,
        ChainType::SUBSTRATE => transaction,
        ChainType::XRP => transaction,
        ChainType::ICP => transaction,
        ChainType::SOL => transaction,
        ChainType::ADA => ada::encode_for_broadcast(transaction)?,
        ChainType::SUI => transaction,
        ChainType::APT => transaction,
        ChainType::ATOM => transaction,
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

        let result = encode_for_signing(20, tx);

        assert!(result.is_ok());
    }
}
