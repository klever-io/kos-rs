use cardano_serialization_lib::{
    Ed25519Signature, PublicKey, TransactionBody, TransactionWitnessSet, Vkey, Vkeywitness,
    Vkeywitnesses,
};
use kos::chains::ada::models::RosettaTransaction;
use kos::chains::ada::ADA;
use kos::chains::{Chain, ChainError, Transaction};
use kos::crypto::base64::simple_base64_decode;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let rosetta_tx: RosettaTransaction = ciborium::de::from_reader(transaction.raw_data.as_slice())
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let metadata = hex::decode(rosetta_tx.0).unwrap();

    let tx_body = TransactionBody::from_bytes(metadata)
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let hash = tx_body.to_bytes();

    transaction.tx_hash = hash;

    Ok(transaction)
}

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    public_key: Vec<u8>,
) -> Result<Transaction, ChainError> {
    let mut rosetta_tx: RosettaTransaction =
        ciborium::de::from_reader(transaction.raw_data.as_slice())
            .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let metadata = hex::decode(rosetta_tx.0).unwrap();

    let tx_body = TransactionBody::from_bytes(metadata)
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let mut witness_set = TransactionWitnessSet::new();

    let pbk = PublicKey::from_bytes(public_key.as_ref())
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let v_key = Vkey::new(&pbk);

    let ed25519_signature = Ed25519Signature::from_bytes(transaction.signature.clone())
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let mut v_key_witnesses = Vkeywitnesses::new();

    let v_key = Vkeywitness::new(&v_key, &ed25519_signature);

    v_key_witnesses.add(&v_key);

    witness_set.set_vkeys(&v_key_witnesses);

    let cardano_tx = cardano_serialization_lib::Transaction::new(&tx_body, &witness_set, None);

    rosetta_tx.0 = cardano_tx.to_hex();

    let new_raw = Vec::new();

    ciborium::ser::into_writer(&rosetta_tx, new_raw.clone())
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    transaction.raw_data = new_raw;

    Ok(transaction)
}

#[cfg(test)]
#[test]
fn test_encode_for_sign() {
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .to_string();
    let ada = ADA {};

    let seed = ada.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
    let path = ada.get_path(0, false);

    let pvk = ada.derive(seed, path).unwrap();

    let pvk = if pvk.len() == 96 {
        &pvk[..64]
    } else {
        pvk.as_slice()
    };

    let pbk = ada.get_pbk(pvk.to_vec()).unwrap();

    let transaction = Transaction {
        raw_data: simple_base64_decode("gnkBNmE0MDA4MTgyNTgyMGQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzEwMDAxODI4MjU4MzkwMWFmMDZmYTVmMWIyOGM5MGJkYzFjODdiYmI2NzMwYmMwZGE5ODY0MjBjNGJkMDBmZDRlNWRkMWYyYWViMGM3NDdjNjhhNDAzYzJlY2UwNWE3OTg4MWVmZTk0YWVjMmVjOTIyZmU0YmQxYzA4ZTNkNjMxYTAwMGY0MjQwODI1ODFkNjFkNTVmNDUzZjkzOTU0NzU1OTEzOTkxZDIxMTk1MmU0YmRkZmNjZDllZWE3ZTQyNDk2N2E3NzlmNDFhMDEwZjcxYTEwMjFhMDAwMzM2ZGYwMzFhMDhmNzFlOTWham9wZXJhdGlvbnOBpnRvcGVyYXRpb25faWRlbnRpZmllcqFlaW5kZXgAZHR5cGVlaW5wdXRmc3RhdHVzYGdhY2NvdW50oWdhZGRyZXNzeDphZGRyMXY4MjQ3M2ZsancyNXc0djM4eGdheXl2NDllOWFtbHhkbm00OHVzamZ2N25obmFxOXYyNTl1ZmFtb3VudKJldmFsdWVoMTkwMDAwMDBoY3VycmVuY3miZnN5bWJvbGNBREFoZGVjaW1hbHMGa2NvaW5fY2hhbmdlom9jb2luX2lkZW50aWZpZXKhamlkZW50aWZpZXJ4QmQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzE6MGtjb2luX2FjdGlvbmpjb2luX3NwZW50").unwrap(),
        tx_hash: vec![],
        signature: vec![],
        options: None,
    };

    let result = encode_for_sign(transaction).unwrap();
}
