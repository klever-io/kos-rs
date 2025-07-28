use crate::chains::sol::models::SolanaTransaction;
use kos::chains::{ChainError, Transaction};

mod models;

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let sol_tx = SolanaTransaction::decode(&transaction.raw_data)?;

    if (sol_tx.message.header.num_required_signatures as usize) < 1 {
        return Err(ChainError::InvalidTransactionHeader);
    }
    if sol_tx.message.account_keys.is_empty() {
        return Err(ChainError::InvalidAccountLength);
    }
    if sol_tx.message.recent_blockhash.iter().all(|&x| x == 0)
        || sol_tx.message.recent_blockhash.iter().all(|&x| x == 1)
    {
        return Err(ChainError::InvalidBlockhash);
    }

    transaction.tx_hash = sol_tx.message.encode()?;

    Ok(transaction)
}

pub fn is_signature_empty(signature: &[u8]) -> bool {
    signature.iter().all(|&byte| byte == 0)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let mut sol_tx = SolanaTransaction::decode(&transaction.raw_data)?;

    if transaction.signature.len() != 64 {
        return Err(ChainError::InvalidSignatureLength);
    }
    if sol_tx.signatures.len() > 1 {
        for i in 0..sol_tx.signatures.len() {
            if is_signature_empty(&sol_tx.signatures[i]) {
                sol_tx.signatures[i] = transaction.signature.clone();
                break;
            }
        }
    } else {
        sol_tx.signatures = vec![transaction.signature.clone()];
    }

    transaction.tx_hash = sol_tx.signatures[0].clone();

    let signed_tx = sol_tx.encode()?;

    transaction.raw_data = signed_tx;
    Ok(transaction)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_with_multiple_signatures_for_sign() {
        let raw_tx = hex::decode(
            "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e204531af552c290aa00f4118af67c11c7d054e6472e4acbe153a453093b9e5952e5384ab044da639cc9799f96a099cf624fb09dd704f4188f8e94eaa64e830502000305f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa418cdc1f7007a4280a83124c2e09f624831f4f85fa87687f6580ebb65b6bfccf1000000000000000000000000000000000000000000000000000000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a000000001197f68f8dab0cc4117dfcfb19b13828a08538c1e07efb8908bea9a9f08e2bec02020200013400000000006cbb0000000000c80000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc000000000030201047400000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa400000000000000000000000000000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4"
        ).unwrap();
        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "02000305f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa418cdc1f7007a4280a83124c2e09f624831f4f85fa87687f6580ebb65b6bfccf1000000000000000000000000000000000000000000000000000000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a000000001197f68f8dab0cc4117dfcfb19b13828a08538c1e07efb8908bea9a9f08e2bec02020200013400000000006cbb0000000000c80000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc000000000030201047400000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa400000000000000000000000000000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4"
        );
    }

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode(
            "00010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000"
        ).unwrap();
        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash),
            "010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000"
        );
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode(
            "00010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000"
        ).unwrap();
        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![
                // 64 bytes of signature
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            ],
            options: None,
        };

        let result = encode_for_broadcast(tx).unwrap();

        assert_eq!(hex::encode(result.raw_data), "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000");
        assert_eq!(
            hex::encode(result.signature),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
    }
    #[test]
    fn test_encode_for_broadcast_for_multiple_signs() {
        let raw_tx = hex::decode(
         "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e204531af552c290aa00f4118af67c11c7d054e6472e4acbe153a453093b9e5952e5384ab044da639cc9799f96a099cf624fb09dd704f4188f8e94eaa64e830502000305f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa418cdc1f7007a4280a83124c2e09f624831f4f85fa87687f6580ebb65b6bfccf1000000000000000000000000000000000000000000000000000000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a000000001197f68f8dab0cc4117dfcfb19b13828a08538c1e07efb8908bea9a9f08e2bec02020200013400000000006cbb0000000000c80000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc000000000030201047400000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa400000000000000000000000000000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4"
        ).unwrap();
        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            ],
            options: None,
        };

        let result = encode_for_broadcast(tx).unwrap();

        assert_eq!(hex::encode(result.raw_data), "02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fe204531af552c290aa00f4118af67c11c7d054e6472e4acbe153a453093b9e5952e5384ab044da639cc9799f96a099cf624fb09dd704f4188f8e94eaa64e830502000305f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa418cdc1f7007a4280a83124c2e09f624831f4f85fa87687f6580ebb65b6bfccf1000000000000000000000000000000000000000000000000000000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a000000001197f68f8dab0cc4117dfcfb19b13828a08538c1e07efb8908bea9a9f08e2bec02020200013400000000006cbb0000000000c80000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc000000000030201047400000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa400000000000000000000000000000000f77c84f2dbf2352fc7b95d4897b3314bbc0f16f5cc9eb5c1efae0a9cf63eeaa4");
        assert_eq!(
            hex::encode(result.signature),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
    }
}
