mod models;

use crate::chains::substrate::models::ExtrinsicPayload;
use crate::KosCodedAccount;
use kos::chains::{ChainError, ChainOptions, Transaction};
use kos::crypto::hash::blake2b_digest;

pub fn encode_for_sign(
    mut transaction: Transaction,
    account: KosCodedAccount,
) -> Result<Transaction, ChainError> {
    let extrinsic = unwrap_extrinsic(transaction.clone(), account.clone())?;

    let tx_hash = {
        let full_unsigned_payload_scale_bytes = extrinsic.to_bytes();

        // If payload is longer than 256 bytes, we hash it and sign the hash instead:
        if full_unsigned_payload_scale_bytes.len() > 256 {
            blake2b_digest(&full_unsigned_payload_scale_bytes).to_vec()
        } else {
            full_unsigned_payload_scale_bytes
        }
    };

    transaction.tx_hash = tx_hash;

    Ok(transaction)
}

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    account: KosCodedAccount,
) -> Result<Transaction, ChainError> {
    let extrinsic = unwrap_extrinsic(transaction.clone(), account.clone())?;

    let public_key: [u8; 32] = hex::decode(account.public_key)
        .unwrap()
        .try_into()
        .map_err(|_| ChainError::InvalidPublicKey)?;

    transaction.raw_data = extrinsic.encode_with_signature(&public_key, &transaction.signature);
    Ok(transaction)
}

fn unwrap_extrinsic(
    transaction: Transaction,
    account: KosCodedAccount,
) -> Result<ExtrinsicPayload, ChainError> {
    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    match options {
        ChainOptions::SUBSTRATE {
            call,
            era,
            nonce,
            tip,
            block_hash,
            genesis_hash,
            spec_version,
            transaction_version,
            app_id,
        } => {
            let genesis_hash: [u8; 32] = genesis_hash
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::InvalidOptions)?;

            let block_hash: [u8; 32] = block_hash
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::InvalidOptions)?;

            // Other chains may have different requirements for mode and metadata_hash
            let (mode, metadata_hash) = match account.chain_id {
                29 => (None, None),
                _ => (Some(0u8), Some(0u8)),
            };

            Ok(ExtrinsicPayload {
                call,
                era,
                nonce,
                tip,
                mode,
                spec_version,
                transaction_version,
                genesis_hash,
                block_hash,
                metadata_hash,
                app_id,
            })
        }
        _ => Err(ChainError::InvalidOptions),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tx_dot() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0503000c2441b8cedbfc7a2edc0968b9a535819969d3e9e0998680babb5827287fc07004",
                )
                .unwrap(),
                era: hex::decode("d501").unwrap(),
                nonce: 27,
                tip: 0,
                block_hash: hex::decode(
                    "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                )
                .unwrap(),
                spec_version: 1003004,
                transaction_version: 26,
                app_id: None,
            }),
        };

        let acc = KosCodedAccount {
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
            chain_id: 21,
            address: "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo".to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0503000c2441b8cedbfc7a2edc0968b9a535819969d3e9e0998680babb5827287fc07004d5016c0000fc4d0f001a00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c300"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "3102840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54d5016c00000503000c2441b8cedbfc7a2edc0968b9a535819969d3e9e0998680babb5827287fc07004");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }

    #[test]
    fn test_tx_ksm() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0403004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904",
                )
                .unwrap(),
                era: hex::decode("4502").unwrap(),
                nonce: 87,
                tip: 0,
                block_hash: hex::decode(
                    "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
                )
                .unwrap(),
                spec_version: 1003003,
                transaction_version: 26,
                app_id: None,
            }),
        };

        let acc = KosCodedAccount {
            chain_id: 27,
            address: "Etp93jqLeBY8TczVXDJQoWNvMoY8VBSXoYNBYou5ghUBeC1".to_string(),
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0403004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd590445025d010000fb4d0f001a000000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe00"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "3502840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad5445025d0100000403004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }
    #[test]
    fn test_tx_avail() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();
        let nonce = u32::from_str_radix("0x00000008".trim_start_matches("0x"), 16).unwrap();
        let spec_version = u32::from_str_radix("0x00000028".trim_start_matches("0x"), 16).unwrap();
        let transaction_version =
            u32::from_str_radix("0x00000001".trim_start_matches("0x"), 16).unwrap();

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0603004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904",
                )
                .unwrap(),
                era: hex::decode("b501").unwrap(),
                nonce,
                tip: 0,
                block_hash: hex::decode(
                    "0e15fed86501da447cae3b7361fc14a087f309aeb751085d71a988aa4bb4a811",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "b91746b45e0346cc2f815a520b9c6cb4d5c0902af848db0a80f85932d2e8276a",
                )
                .unwrap(),
                spec_version,
                transaction_version,
                app_id: Some(0),
            }),
        };

        let acc = KosCodedAccount {
            chain_id: 62,
            address: "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH".to_string(),
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0603004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904b5012000002800000001000000b91746b45e0346cc2f815a520b9c6cb4d5c0902af848db0a80f85932d2e8276a0e15fed86501da447cae3b7361fc14a087f309aeb751085d71a988aa4bb4a811"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "3102840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54b5012000000603004e0edd04c47b1adc3b21dcd8671a5d90a1c2eb75fb60d293a9086f2626dbcd5904");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }

    #[test]
    fn test_tx_reef() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();
        let nonce = 24;
        let spec_version = 10;
        let transaction_version = 2;

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0603002010065fd68017f85177f9acf9809ab6e359ec7631c9f972fe3ef9697af0931304",
                )
                .unwrap(),
                era: hex::decode("1503").unwrap(),
                nonce,
                tip: 0,
                block_hash: hex::decode(
                    "567c2424bbef73128c80b319cec4fc6140e122b23ef22096f2be41a651cad76b",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "7834781d38e4798d548e34ec947d19deea29df148a7bf32484b7b24dacf8d4b7",
                )
                .unwrap(),
                spec_version,
                transaction_version,
                app_id: None,
            }),
        };

        let acc = KosCodedAccount {
            chain_id: 29,
            address: "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH".to_string(),
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0603002010065fd68017f85177f9acf9809ab6e359ec7631c9f972fe3ef9697af0931304150360000a000000020000007834781d38e4798d548e34ec947d19deea29df148a7bf32484b7b24dacf8d4b7567c2424bbef73128c80b319cec4fc6140e122b23ef22096f2be41a651cad76b"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "2d02840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54150360000603002010065fd68017f85177f9acf9809ab6e359ec7631c9f972fe3ef9697af0931304");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }

    #[test]
    fn test_tx_kar() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();
        let nonce = 0;
        let spec_version = 2280;
        let transaction_version = 2;

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0a03006d6f646c6163612f696e6374000000000000000000000000000000000000000004",
                )
                .unwrap(),
                era: hex::decode("f502").unwrap(),
                nonce,
                tip: 0,
                block_hash: hex::decode(
                    "4e29888d26fcdbdc19016d7d9ea2aa4f98e4a53a3cd1602008ba82def26eeb27",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "baf5aabe40646d11f0ee8abbdc64f4a4b7674925cba08e4a05ff9ebed6e2126b",
                )
                .unwrap(),
                spec_version,
                transaction_version,
                app_id: None,
            }),
        };

        let acc = KosCodedAccount {
            chain_id: 41,
            address: "qcmgzzFePRu4p3mviVSgD6voGfJTaxZfSs9sefhrpGPsejg".to_string(),
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0a03006d6f646c6163612f696e6374000000000000000000000000000000000000000004f502000000e808000002000000baf5aabe40646d11f0ee8abbdc64f4a4b7674925cba08e4a05ff9ebed6e2126b4e29888d26fcdbdc19016d7d9ea2aa4f98e4a53a3cd1602008ba82def26eeb2700"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "3102840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54f5020000000a03006d6f646c6163612f696e6374000000000000000000000000000000000000000004");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }
    #[test]
    fn test_tx_aca() {
        let raw_tx = hex::decode("b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080").unwrap();
        let nonce = 4981;
        let spec_version = 2280;
        let transaction_version = 3;

        let mut tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::SUBSTRATE {
                call: hex::decode(
                    "0a03006d6f646c6163612f6465786d000000000000000000000000000000000000000004",
                )
                .unwrap(),
                era: hex::decode("0503").unwrap(),
                nonce,
                tip: 0,
                block_hash: hex::decode(
                    "c64067e6203771c6a0f0a8cbd1cdb710c2a9e453733f47b62014cb9d39220723",
                )
                .unwrap(),
                genesis_hash: hex::decode(
                    "fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c",
                )
                .unwrap(),
                spec_version,
                transaction_version,
                app_id: None,
            }),
        };

        let acc = KosCodedAccount {
            chain_id: 46,
            address: "23C6Cz54QyBMNvrhjnFVS1dn6EwtZxDc3KyR71xJnXTNSDst".to_string(),
            public_key: "66933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972"
                .to_string(),
        };

        let result = encode_for_sign(tx.clone(), acc.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "0a03006d6f646c6163612f6465786d0000000000000000000000000000000000000000040503d54d0000e808000003000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64cc64067e6203771c6a0f0a8cbd1cdb710c2a9e453733f47b62014cb9d3922072300"
        );

        tx.signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94,
            0x7b, 0x2c, 0xf5, 0x43, 0x58, 0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a,
            0x45, 0x77, 0x6b, 0x59, 0x90, 0xa5, 0x49, 0xad, 0x54,
        ];

        let signed_tx = encode_for_broadcast(tx.clone(), acc).unwrap();

        assert_eq!(hex::encode(signed_tx.raw_data), "3502840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79723045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad540503d54d00000a03006d6f646c6163612f6465786d000000000000000000000000000000000000000004");
        assert_eq!(
            hex::encode(signed_tx.signature),
            "3045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54073045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54"
        );
    }
}
