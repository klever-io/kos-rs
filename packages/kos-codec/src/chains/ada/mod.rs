use crate::KosCodedAccount;
use cardano_serialization_lib::{
    Ed25519Signature, PublicKey, TransactionBody, TransactionWitnessSet, Vkey, Vkeywitness,
    Vkeywitnesses,
};
use kos::chains::ada::models::RosettaTransaction;
use kos::chains::ada::ADA;
use kos::chains::util::hex_string_to_vec;
use kos::chains::{ada, Chain, ChainError, Transaction};
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
    account: KosCodedAccount,
) -> Result<Transaction, ChainError> {
    let mut rosetta_tx: RosettaTransaction =
        ciborium::de::from_reader(transaction.raw_data.as_slice())
            .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let metadata = hex::decode(rosetta_tx.0).unwrap();

    let tx_body = TransactionBody::from_bytes(metadata)
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let mut witness_set = TransactionWitnessSet::new();

    let private_key = hex_string_to_vec(account.private_key.as_ref())?;

    // Reducing from xprivkey to privkey
    let pvk = if private_key.len() == 96 {
        &private_key[..64]
    } else {
        private_key.as_slice()
    };

    let public_key = ADA {}.get_pbk(pvk.to_vec())?;

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

    let transaction = Transaction {
        raw_data: simple_base64_decode("gnkBNmE0MDA4MTgyNTgyMGQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzEwMDAxODI4MjU4MzkwMWFmMDZmYTVmMWIyOGM5MGJkYzFjODdiYmI2NzMwYmMwZGE5ODY0MjBjNGJkMDBmZDRlNWRkMWYyYWViMGM3NDdjNjhhNDAzYzJlY2UwNWE3OTg4MWVmZTk0YWVjMmVjOTIyZmU0YmQxYzA4ZTNkNjMxYTAwMGY0MjQwODI1ODFkNjFkNTVmNDUzZjkzOTU0NzU1OTEzOTkxZDIxMTk1MmU0YmRkZmNjZDllZWE3ZTQyNDk2N2E3NzlmNDFhMDEwZjcxYTEwMjFhMDAwMzM2ZGYwMzFhMDhmNzFlOTWham9wZXJhdGlvbnOBpnRvcGVyYXRpb25faWRlbnRpZmllcqFlaW5kZXgAZHR5cGVlaW5wdXRmc3RhdHVzYGdhY2NvdW50oWdhZGRyZXNzeDphZGRyMXY4MjQ3M2ZsancyNXc0djM4eGdheXl2NDllOWFtbHhkbm00OHVzamZ2N25obmFxOXYyNTl1ZmFtb3VudKJldmFsdWVoMTkwMDAwMDBoY3VycmVuY3miZnN5bWJvbGNBREFoZGVjaW1hbHMGa2NvaW5fY2hhbmdlom9jb2luX2lkZW50aWZpZXKhamlkZW50aWZpZXJ4QmQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzE6MGtjb2luX2FjdGlvbmpjb2luX3NwZW50").unwrap(),
        tx_hash: vec![],
        signature: vec![],
        options: None,
    };

    let result = encode_for_sign(transaction).unwrap();

    let signed = ada.sign_tx(pvk, result.clone()).unwrap();

    assert_eq!(hex::encode(signed.signature), "bde604cf8e8ca6a5fd150a083e6c51e220f7e80cb9b8181b0f438aee0e2c34f4cf32aca0568c4b30ea1215bfc3cc2290384491b7ac618ccdbcbf3d3e530a9803".to_string());
    assert_eq!(hex::encode(signed.tx_hash), "a400d9010281825820d19c054099d89e22b5be557e24c02314de7ac93d7d1e602d3bbfc8684679d3c100018282583901af06fa5f1b28c90bdc1c87bbb6730bc0da986420c4bd00fd4e5dd1f2aeb0c747c68a403c2ece05a79881efe94aec2ec922fe4bd1c08e3d631a000f424082581d61d55f453f93954755913991d211952e4bddfccd9eea7e424967a779f41a010f71a1021a000336df031a08f71e95".to_string())
}

#[test]
fn test_encode_for_broadcast() {
    let raw_tx = simple_base64_decode("gnkBNmE0MDA4MTgyNTgyMGQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzEwMDAxODI4MjU4MzkwMWFmMDZmYTVmMWIyOGM5MGJkYzFjODdiYmI2NzMwYmMwZGE5ODY0MjBjNGJkMDBmZDRlNWRkMWYyYWViMGM3NDdjNjhhNDAzYzJlY2UwNWE3OTg4MWVmZTk0YWVjMmVjOTIyZmU0YmQxYzA4ZTNkNjMxYTAwMGY0MjQwODI1ODFkNjFkNTVmNDUzZjkzOTU0NzU1OTEzOTkxZDIxMTk1MmU0YmRkZmNjZDllZWE3ZTQyNDk2N2E3NzlmNDFhMDEwZjcxYTEwMjFhMDAwMzM2ZGYwMzFhMDhmNzFlOTWham9wZXJhdGlvbnOBpnRvcGVyYXRpb25faWRlbnRpZmllcqFlaW5kZXgAZHR5cGVlaW5wdXRmc3RhdHVzYGdhY2NvdW50oWdhZGRyZXNzeDphZGRyMXY4MjQ3M2ZsancyNXc0djM4eGdheXl2NDllOWFtbHhkbm00OHVzamZ2N25obmFxOXYyNTl1ZmFtb3VudKJldmFsdWVoMTkwMDAwMDBoY3VycmVuY3miZnN5bWJvbGNBREFoZGVjaW1hbHMGa2NvaW5fY2hhbmdlom9jb2luX2lkZW50aWZpZXKhamlkZW50aWZpZXJ4QmQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzE6MGtjb2luX2FjdGlvbmpjb2luX3NwZW50").unwrap();

    let signature = hex::decode("bde604cf8e8ca6a5fd150a083e6c51e220f7e80cb9b8181b0f438aee0e2c34f4cf32aca0568c4b30ea1215bfc3cc2290384491b7ac618ccdbcbf3d3e530a9803").unwrap();

    let tx = Transaction {
        raw_data: raw_tx,
        tx_hash: hex::decode("a400d9010281825820d19c054099d89e22b5be557e24c02314de7ac93d7d1e602d3bbfc8684679d3c100018282583901af06fa5f1b28c90bdc1c87bbb6730bc0da986420c4bd00fd4e5dd1f2aeb0c747c68a403c2ece05a79881efe94aec2ec922fe4bd1c08e3d631a000f424082581d61d55f453f93954755913991d211952e4bddfccd9eea7e424967a779f41a010f71a1021a000336df031a08f71e95").unwrap(),
        signature,
        options: None,
    };

    let account = KosCodedAccount {
        chain_id: ada::BASE_ID,
        address: "addr1vy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7ss7lxrqp".to_string(),
        public_key: "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a".to_string(),
        private_key: "105d2ef2192150655a926bca9cccf5e2f6e496efa9580508192e1f4a790e6f53de06529129511d1cacb0664bcf04853fdc0055a47cc6d2c6d20512702076065288848e8af62a27a57e982215741c9eac17e6e45cbfd6ea65a0e0dcc03bb777b2".to_string(),
    };

    let result = encode_for_broadcast(tx.clone(), account).unwrap();

    assert_eq!(hex::encode(result.signature), "bde604cf8e8ca6a5fd150a083e6c51e220f7e80cb9b8181b0f438aee0e2c34f4cf32aca0568c4b30ea1215bfc3cc2290384491b7ac618ccdbcbf3d3e530a9803".to_string());
    assert_eq!(hex::encode(result.raw_data), "a400d9010281825820d19c054099d89e22b5be557e24c02314de7ac93d7d1e602d3bbfc8684679d3c100018282583901af06fa5f1b28c90bdc1c87bbb6730bc0da986420c4bd00fd4e5dd1f2aeb0c747c68a403c2ece05a79881efe94aec2ec922fe4bd1c08e3d631a000f424082581d61d55f453f93954755913991d211952e4bddfccd9eea7e424967a779f41a010f71a1021a000336df031a08f71e95".to_string())
}
