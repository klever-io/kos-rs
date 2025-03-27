mod models;

use crate::chains::apt::models::{ED25519Signature, JSONSignature};
use crate::KosCodedAccount;
use kos::chains::{ChainError, Transaction};

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    account: KosCodedAccount,
) -> Result<Transaction, ChainError> {
    let pub_key = hex::decode(account.public_key).unwrap();

    let transaction_signature = JSONSignature::ED25519(ED25519Signature {
        public_key: hex::encode(pub_key),
        signature: hex::encode(transaction.signature.clone()),
    });

    let signature_json = serde_json::to_string(&transaction_signature).unwrap();

    transaction.signature = signature_json.as_bytes().to_vec();

    Ok(transaction)
}
