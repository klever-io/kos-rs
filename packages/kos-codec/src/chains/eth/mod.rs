mod models;

use crate::chains::eth::models::EthereumTransaction;
use alloy_dyn_abi::TypedData;
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

pub fn encode_sign_typed(message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
    if let Ok(data) = std::str::from_utf8(&message) {
        if let Ok(typed_data) = serde_json::from_str::<TypedData>(data) {
            let digest = typed_data
                .eip712_signing_hash()
                .map_err(|e| ChainError::InvalidData(format!("EIP-712 hash error: {e}")))?;
            return Ok(digest.to_vec());
        }
    }

    Err(ChainError::InvalidData("invalid typed data".to_string()))
}

pub fn encode_sign_message(message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
    let to_sign = [
        kos::chains::eth::ETH_MESSAGE_PREFIX,
        message.len().to_string().as_bytes(),
        &message[..],
    ]
    .concat();
    Ok(keccak256_digest(&to_sign[..]).to_vec())
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

        assert_eq!(hex::encode(signed_tx.raw_data), "b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080");
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

        assert_eq!(hex::encode(signed_tx.raw_data), "b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }

    #[test]
    fn test_sign_typed_data() {
        let data = r#"{
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Person": [
                    { "name": "name", "type": "string" },
                    { "name": "wallet", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "Person" },
                    { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let message = data.as_bytes();

        let signature = encode_sign_typed(message.to_vec()).unwrap();
        assert_eq!(
            hex::encode(signature),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn test_encode_sign_message() {
        let message_bytes = "test message".as_bytes().to_vec();

        let signature = encode_sign_message(message_bytes).unwrap();

        assert_eq!(
            hex::encode(signature),
            "3e2d111c8c52a5ef0ba64fe4d85e32a5153032367ec44aaae0a4e2d1bfb9bebd"
        );
    }
}
