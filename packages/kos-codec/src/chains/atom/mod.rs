use cosmrs::proto::cosmos::tx::v1beta1::Tx;
use cosmrs::proto::prost::Message;
use kos::chains::{ChainError, ChainOptions, Transaction};

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let tx_decoded: Tx = Tx::decode(transaction.raw_data.as_ref()).unwrap();

    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    let (chain_id, account_number) = match options {
        ChainOptions::COSMOS {
            chain_id,
            account_number,
        } => (chain_id, account_number),
        _ => {
            return Err(ChainError::InvalidOptions);
        }
    };

    let sign_doc = cosmrs::proto::cosmos::tx::v1beta1::SignDoc {
        account_number,
        auth_info_bytes: tx_decoded.auth_info.clone().unwrap().encode_to_vec(),
        body_bytes: tx_decoded.body.clone().unwrap().encode_to_vec(),
        chain_id: chain_id.to_string(),
    };

    transaction.raw_data = sign_doc.encode_to_vec();
    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut tx_decoded = Tx::decode(transaction.clone().raw_data.as_ref()).unwrap();

    let mut signatures: Vec<Vec<u8>> = Vec::new();
    signatures.extend_from_slice(&[transaction.clone().signature]);
    tx_decoded.signatures = signatures;

    let tx_raw =
        cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(tx_decoded.encode_to_vec().as_ref())
            .unwrap();

    transaction.raw_data = tx_raw.encode_to_vec();

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode("0a8d010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112650a4e0a440a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b65791221020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180912130a0d0a057561746f6d12043235303010a9da06").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(kos::chains::ChainOptions::COSMOS {
                chain_id: "cosmoshub-4".to_string(),
                account_number: 1980337,
            }),
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(hex::encode(result.raw_data), "0a8d010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112650a4e0a440a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b65791221020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180912130a0d0a057561746f6d12043235303010a9da061a0b636f736d6f736875622d342009");
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode("0a8d010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112650a4e0a440a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b65791221020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180912130a0d0a057561746f6d12043235303010a9da061a0b636f736d6f736875622d342009").unwrap();

        let signature = hex::decode("1234").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature,
            options: Some(kos::chains::ChainOptions::COSMOS {
                chain_id: "cosmoshub-4".to_string(),
                account_number: 1980337,
            }),
        };

        let result = encode_for_broadcast(tx.clone()).unwrap();

        assert_eq!(hex::encode(result.raw_data), "1200002200000000240000034a201b009717be61400000000098968068400000000000000c69d4564b964a845ac0000000000000000000000000555344000000000069d33b18d53385f8a3185516c2eda5dedb8ac5c67321031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae74021234811469d33b18d53385f8a3185516c2eda5dedb8ac5c6831469d33b18d53385f8a3185516c2eda5dedb8ac5c6f9ea7c06636c69656e747d077274312e312e31e1f1011201f3b1997562fd742b54d4ebdea1d6aea3d4906b8f100000000000000000000000000000000000000000ff014b4e9c06f24296074f7bc48f92a97916c6dc5ea901dd39c650a96eda48334e70cc4a85b8b2e8502cd310000000000000000000000000000000000000000000");
    }
}
