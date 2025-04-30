mod models;

use crate::chains::eth::models::EthereumTransaction;
use kos::chains::{ChainError, ChainOptions, Transaction};
use kos::crypto::hash::keccak256_digest;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut eth_tx = EthereumTransaction::decode(&transaction.raw_data)?;

    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    let chain_code = match options {
        ChainOptions::EVM { chain_id } => chain_id,
        _ => {
            return Err(ChainError::InvalidOptions);
        }
    };

    //Ensure empty signature
    eth_tx.signature = None;
    if eth_tx.transaction_type == models::TransactionType::Legacy {
        eth_tx.chain_id = Some(chain_code as u64);
    }

    let new_rlp = eth_tx.encode()?;
    let to_sign = keccak256_digest(&new_rlp[..]);

    transaction.tx_hash = to_sign.to_vec();
    Ok(transaction)
}

pub fn encode_for_broadcast(transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut eth_tx = EthereumTransaction::decode(&transaction.raw_data)?;

    let mut signature_bytes: [u8; 65] = [0; 65];
    signature_bytes.copy_from_slice(&transaction.signature[..]);
    eth_tx.signature = Some(signature_bytes);

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_legacy_tx() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::EVM { chain_id: 1 }),
        };

        let result = encode_for_sign(tx.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "5ed21ed1618c98b5b1814565d8d7a63ebc6425997c75b2b857d8692f0b73a64f"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone()).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "02f87101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c054a054ad49a590596b77452a01141de380dd50945843f52c7b94718fd30021024530a0ad49a590596b77452a01141de380dd50945843f52c7b94718fd3002102453007");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }
    #[test]
    fn test_london_tx() {
        let raw_tx = hex::decode("b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080").unwrap();

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::EVM { chain_id: 1 }),
        };

        let result = encode_for_sign(tx.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "8823151a6987f2625239f058e453f5850e3d800b31f1dd60951a7e36e0769c2e"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone()).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "02f8b30182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac054a054ad49a590596b77452a01141de380dd50945843f52c7b94718fd30021024530a0ad49a590596b77452a01141de380dd50945843f52c7b94718fd3002102453007");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }
}
