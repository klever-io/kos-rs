mod constants;
mod transactions;

use kos::chains::{ChainError, Transaction};
use xrpl::core::binarycodec::types::{blob::Blob, XRPLType};

pub fn encode_for_sign(
    mut transaction: Transaction,
    public_key: String,
) -> Result<Transaction, ChainError> {
    let mut decoded_transaction = transactions::decode_factory(transaction.raw_data)?;

    let pbk = hex::decode(public_key).map_err(|_| ChainError::InvalidPublicKey)?;

    decoded_transaction.common_mut().signing_pub_key = Some(Blob::new(Some(pbk.as_ref())).unwrap());

    let buff = decoded_transaction.serialize()?;

    transaction.raw_data = buff;

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut decoded_transaction = transactions::decode_factory(transaction.raw_data)?;

    decoded_transaction.common_mut().txn_signature =
        Some(Blob::new(Some(transaction.signature.as_ref())).unwrap());

    transaction.raw_data = decoded_transaction.serialize()?;
    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::KosCodedAccount;
    use kos::crypto::base64::simple_base64_decode;

    #[test]
    fn test_encode_for_sign() {
        // Example from https://github.com/XRPLF/xrpl-dev-portal/blob/master/_code-samples/tx-serialization/js/test-cases/tx3-binary.txt
        let raw_tx = simple_base64_decode("EgAAIgAAAAAkAAADSiAbAJcXvmFAAAAAAJiWgGhAAAAAAAAADGnUVkuWSoRawAAAAAAAAAAAAAAAAFVTRAAAAAAAadM7GNUzhfijGFUWwu2l3tuKxcZzIQN58Xz6D/11GBgVlL5p/poQRx1t4fQFXG0nRq/Wz4mInnRHMEUCIQDVXtGVP4YK3BvFzZk6u5J/SBVqyjHGRzeGX09P9tAVqAIgYwcE0r0JyOmfJgkMJfEbKPXZahNQRUQCws7ZKzn/26+BFGnTOxjVM4X4oxhVFsLtpd7bisXGgxRp0zsY1TOF+KMYVRbC7aXe24rFxvnqfAZjbGllbnR9B3J0MS4xLjHh8QESAfOxmXVi/XQrVNTr3qHWrqPUkGuPEAAAAAAAAAAAAAAAAAAAAAAAAAAA/wFLTpwG8kKWB097xI+SqXkWxtxeqQHdOcZQqW7aSDNOcMxKhbiy6FAs0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let account = KosCodedAccount {
            chain_id: 20,
            address: "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3".to_string(),
            public_key: "031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae"
                .to_string(),
        };

        let result = encode_for_sign(tx, account.public_key.clone()).unwrap();

        let mut decoded_transaction =
            transactions::decode_factory(result.raw_data.clone()).unwrap();

        assert_eq!(
            hex::encode(
                decoded_transaction
                    .common_mut()
                    .signing_pub_key
                    .as_ref()
                    .unwrap()
                    .as_ref()
            ),
            account.public_key
        );

        assert_eq!(hex::encode(result.raw_data), "1200002200000000240000034a201b009717be61400000000098968068400000000000000c69d4564b964a845ac0000000000000000000000000555344000000000069d33b18d53385f8a3185516c2eda5dedb8ac5c67321031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae74473045022100d55ed1953f860adc1bc5cd993abb927f48156aca31c64737865f4f4ff6d015a80220630704d2bd09c8e99f26090c25f11b28f5d96a1350454402c2ced92b39ffdbaf811469d33b18d53385f8a3185516c2eda5dedb8ac5c6831469d33b18d53385f8a3185516c2eda5dedb8ac5c6f9ea7c06636c69656e747d077274312e312e31e1f1011201f3b1997562fd742b54d4ebdea1d6aea3d4906b8f100000000000000000000000000000000000000000ff014b4e9c06f24296074f7bc48f92a97916c6dc5ea901dd39c650a96eda48334e70cc4a85b8b2e8502cd310000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode("1200002200000000240000034a201b009717be61400000000098968068400000000000000c69d4564b964a845ac0000000000000000000000000555344000000000069d33b18d53385f8a3185516c2eda5dedb8ac5c67321031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae74473045022100d55ed1953f860adc1bc5cd993abb927f48156aca31c64737865f4f4ff6d015a80220630704d2bd09c8e99f26090c25f11b28f5d96a1350454402c2ced92b39ffdbaf811469d33b18d53385f8a3185516c2eda5dedb8ac5c6831469d33b18d53385f8a3185516c2eda5dedb8ac5c6f9ea7c06636c69656e747d077274312e312e31e1f1011201f3b1997562fd742b54d4ebdea1d6aea3d4906b8f100000000000000000000000000000000000000000ff014b4e9c06f24296074f7bc48f92a97916c6dc5ea901dd39c650a96eda48334e70cc4a85b8b2e8502cd310000000000000000000000000000000000000000000").unwrap();

        let signature = hex::decode("1234").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature,
            options: None,
        };

        let result = encode_for_broadcast(tx.clone()).unwrap();

        let mut decoded_transaction =
            transactions::decode_factory(result.raw_data.clone()).unwrap();

        assert_eq!(
            hex::encode(
                decoded_transaction
                    .common_mut()
                    .txn_signature
                    .as_ref()
                    .unwrap()
                    .as_ref()
            ),
            hex::encode(tx.signature)
        );

        assert_eq!(hex::encode(result.raw_data), "1200002200000000240000034a201b009717be61400000000098968068400000000000000c69d4564b964a845ac0000000000000000000000000555344000000000069d33b18d53385f8a3185516c2eda5dedb8ac5c67321031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae74021234811469d33b18d53385f8a3185516c2eda5dedb8ac5c6831469d33b18d53385f8a3185516c2eda5dedb8ac5c6f9ea7c06636c69656e747d077274312e312e31e1f1011201f3b1997562fd742b54d4ebdea1d6aea3d4906b8f100000000000000000000000000000000000000000ff014b4e9c06f24296074f7bc48f92a97916c6dc5ea901dd39c650a96eda48334e70cc4a85b8b2e8502cd310000000000000000000000000000000000000000000");
    }
}
