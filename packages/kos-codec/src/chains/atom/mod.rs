use cosmrs::proto::cosmos::tx::v1beta1::Tx;
use cosmrs::proto::prost::Message;
use kos::chains::{ChainError, ChainOptions, Transaction};

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let tx_decoded: Tx = Tx::decode(transaction.raw_data.as_ref())
        .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;

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

    let auth_info_bytes = tx_decoded
        .auth_info
        .ok_or_else(|| ChainError::InvalidTransaction("missing auth_info".to_string()))?
        .encode_to_vec();

    let body_bytes = tx_decoded
        .body
        .ok_or_else(|| ChainError::InvalidTransaction("missing body".to_string()))?
        .encode_to_vec();

    let sign_doc = cosmrs::proto::cosmos::tx::v1beta1::SignDoc {
        account_number,
        auth_info_bytes,
        body_bytes,
        chain_id: chain_id.to_string(),
    };

    transaction.raw_data = sign_doc.encode_to_vec();
    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut tx_decoded = Tx::decode(transaction.clone().raw_data.as_ref())
        .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;

    let mut signatures: Vec<Vec<u8>> = Vec::new();
    signatures.extend_from_slice(&[transaction.clone().signature]);
    tx_decoded.signatures = signatures;

    let tx_raw =
        cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(tx_decoded.encode_to_vec().as_ref())
            .map_err(|_| ChainError::DecodeRawTx)?;

    transaction.raw_data = tx_raw.encode_to_vec();

    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode("0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801181112130a0d0a057561746f6d12043235303010a7e506").unwrap();

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

        assert_eq!(hex::encode(result.raw_data), "0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801181112130a0d0a057561746f6d12043235303010a7e5061a0b636f736d6f736875622d3420b1ef78");
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode("0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801181112130a0d0a057561746f6d12043235303010a7e5061a0b636f736d6f736875622d3420b1ef78").unwrap();

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

        assert_eq!(hex::encode(result.raw_data), "0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801181112130a0d0a057561746f6d12043235303010a7e5061a021234");
    }
}
