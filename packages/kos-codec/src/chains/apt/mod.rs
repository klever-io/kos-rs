mod models;

use crate::chains::apt::models::{ED25519Signature, JSONSignature};
use crate::KosCodedAccount;
use kos::chains::{ChainError, Transaction};

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    account: KosCodedAccount,
) -> Result<Transaction, ChainError> {
    let pub_key = hex::decode(account.public_key).map_err(|_| ChainError::InvalidPublicKey)?;

    let transaction_signature = JSONSignature::ED25519(ED25519Signature {
        public_key: format!("0x{:}", hex::encode(&pub_key)),
        signature: format!("0x{:}", hex::encode(&transaction.signature)),
    });

    let signature_json =
        serde_json::to_string(&transaction_signature).map_err(|_| ChainError::InvalidSignature)?;

    transaction.signature = signature_json.as_bytes().to_vec();

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use crate::chains::apt::encode_for_broadcast;
    use crate::chains::apt::models::{ED25519Signature, JSONSignature};
    use crate::KosCodedAccount;
    use kos::chains::Transaction;

    #[test]
    fn test_encode_for_broadcast() {
        let transaction = Transaction {
            raw_data: vec![1, 2, 3, 4],
            tx_hash: vec![],
            signature: vec![5, 6, 7, 8],
            options: None,
        };

        let account = KosCodedAccount {
            chain_id: 0,
            address: "".to_string(),
            public_key: "1234567890abcdef".to_string(),
        };

        let result = encode_for_broadcast(transaction, account);

        assert!(result.is_ok());

        let transaction = result.unwrap();

        let signature_json = String::from_utf8(transaction.signature).unwrap();

        let signature: JSONSignature = serde_json::from_str(&signature_json).unwrap();

        match signature {
            JSONSignature::ED25519(ED25519Signature {
                public_key,
                signature,
            }) => {
                assert_eq!(public_key, "0x1234567890abcdef");
                assert_eq!(signature, "0x05060708");
            }
            _ => panic!("Invalid signature type"),
        }
    }
}
