use crate::KosCodedAccount;
use cardano_serialization_lib::{
    Ed25519Signature, PublicKey, TransactionBody, TransactionWitnessSet, Vkey, Vkeywitness,
    Vkeywitnesses,
};
use kos::chains::ada::models::RosettaTransaction;
use kos::chains::ada::ADA;
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

    let public_key =
        hex::decode(account.public_key.clone()).map_err(|_| ChainError::InvalidPublicKey)?;

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

    let mut new_raw = Vec::new();

    ciborium::ser::into_writer(&rosetta_tx, &mut new_raw)
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
    let ada = ADA::new(false);

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
    };

    let result = encode_for_broadcast(tx.clone(), account).unwrap();

    assert_eq!(hex::encode(result.signature), "bde604cf8e8ca6a5fd150a083e6c51e220f7e80cb9b8181b0f438aee0e2c34f4cf32aca0568c4b30ea1215bfc3cc2290384491b7ac618ccdbcbf3d3e530a9803".to_string());
    assert_eq!(hex::encode(result.raw_data), "827902183834613430306439303130323831383235383230643139633035343039396438396532326235626535353765323463303233313464653761633933643764316536303264336262666338363834363739643363313030303138323832353833393031616630366661356631623238633930626463316338376262623637333062633064613938363432306334626430306664346535646431663261656230633734376336386134303363326563653035613739383831656665393461656332656339323266653462643163303865336436333161303030663432343038323538316436316435356634353366393339353437353539313339393164323131393532653462646466636364396565613765343234393637613737396634316130313066373161313032316130303033333664663033316130386637316539356131303064393031303238313832353832303765613039613334616562623133633938343163373133393762316361626665633564646639353034303532393364656534393663616332663433373438306135383430626465363034636638653863613661356664313530613038336536633531653232306637653830636239623831383162306634333861656530653263333466346366333261636130353638633462333065613132313562666333636332323930333834343931623761633631386363646263626633643365353330613938303366356636a16a6f7065726174696f6e7381a6746f7065726174696f6e5f6964656e746966696572a165696e64657800647479706565696e7075746673746174757360676163636f756e74a16761646472657373783a6164647231763832343733666c6a773235773476333878676179797634396539616d6c78646e6d343875736a6676376e686e617139763235397566616d6f756e74a26576616c75656831393030303030306863757272656e6379a26673796d626f6c6341444168646563696d616c73066b636f696e5f6368616e6765a26f636f696e5f6964656e746966696572a16a6964656e7469666965727842643139633035343039396438396532326235626535353765323463303233313464653761633933643764316536303264336262666338363834363739643363313a306b636f696e5f616374696f6e6a636f696e5f7370656e74".to_string())
}
