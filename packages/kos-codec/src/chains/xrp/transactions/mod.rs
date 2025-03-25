pub mod account_set;
pub mod codec_helper;
pub mod payment;
pub mod transaction_base;
pub mod trust_set;

use crate::chains::xrp::constants;
use kos::chains::ChainError;

use account_set::AccountSetTransaction;
use payment::PaymentTransaction;
use trust_set::TrustSetTransaction;
use xrpl::core::Parser;

pub trait Serialize {
    fn serialize(&self) -> Result<Vec<u8>, ChainError>;
}

pub trait Transaction: Serialize {
    fn common_mut(&mut self) -> &mut transaction_base::TransactionCommon;
}

pub fn decode_factory(tx: Vec<u8>) -> Result<Box<dyn Transaction>, ChainError> {
    let mut binary_parser = xrpl::core::BinaryParser::from(tx.clone());
    let field_info = binary_parser
        .read_field()
        .map_err(|_| ChainError::DecodeRawTx)?;

    if field_info.name != "TransactionType" {
        return Err(ChainError::InvalidData(
            "invalid transaction TransactionType".to_string(),
        ));
    }

    let transaction_type: u16 = binary_parser
        .read_uint16()
        .map_err(|_| ChainError::DecodeRawTx)?;

    match transaction_type {
        constants::TRANSACTION_TYPE_PAYMENT => {
            let fields = codec_helper::decode_transaction(tx.clone())?;
            let payment_transaction =
                PaymentTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(payment_transaction))
        }
        constants::TRANSACTION_TYPE_ACCOUNT_SET => {
            let fields = codec_helper::decode_transaction(tx.clone())?;
            let account_set_transaction =
                AccountSetTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(account_set_transaction))
        }
        constants::TRANSACTION_TYPE_TRUST_SET => {
            let fields = codec_helper::decode_transaction(tx.clone())?;
            let trust_set_transaction =
                TrustSetTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(trust_set_transaction))
        }
        _ => Err(ChainError::InvalidData("invalid transaction".to_string())),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;
    use kos::crypto::base64::simple_base64_decode;

    #[test]
    fn test_decode_payment_tx() {
        // Example from https://github.com/XRPLF/xrpl-dev-portal/blob/master/_code-samples/tx-serialization/js/test-cases/tx3-binary.txt
        let raw_tx = simple_base64_decode("EgAAIgAAAAAkAAADSiAbAJcXvmFAAAAAAJiWgGhAAAAAAAAADGnUVkuWSoRawAAAAAAAAAAAAAAAAFVTRAAAAAAAadM7GNUzhfijGFUWwu2l3tuKxcZzIQN58Xz6D/11GBgVlL5p/poQRx1t4fQFXG0nRq/Wz4mInnRHMEUCIQDVXtGVP4YK3BvFzZk6u5J/SBVqyjHGRzeGX09P9tAVqAIgYwcE0r0JyOmfJgkMJfEbKPXZahNQRUQCws7ZKzn/26+BFGnTOxjVM4X4oxhVFsLtpd7bisXGgxRp0zsY1TOF+KMYVRbC7aXe24rFxvnqfAZjbGllbnR9B3J0MS4xLjHh8QESAfOxmXVi/XQrVNTr3qHWrqPUkGuPEAAAAAAAAAAAAAAAAAAAAAAAAAAA/wFLTpwG8kKWB097xI+SqXkWxtxeqQHdOcZQqW7aSDNOcMxKhbiy6FAs0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "1200002200000000240000034A201B009717BE61400000000098968068400000000000000C69D4564B964A845AC0000000000000000000000000555344000000000069D33B18D53385F8A3185516C2EDA5DEDB8AC5C673210379F17CFA0FFD7518181594BE69FE9A10471D6DE1F4055C6D2746AFD6CF89889E74473045022100D55ED1953F860ADC1BC5CD993ABB927F48156ACA31C64737865F4F4FF6D015A80220630704D2BD09C8E99F26090C25F11B28F5D96A1350454402C2CED92B39FFDBAF811469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6831469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6F9EA7C06636C69656E747D077274312E312E31E1F1011201F3B1997562FD742B54D4EBDEA1D6AEA3D4906B8F100000000000000000000000000000000000000000FF014B4E9C06F24296074F7BC48F92A97916C6DC5EA901DD39C650A96EDA48334E70CC4A85B8B2E8502CD310000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_encode_payment_tx() {
        let raw_tx = simple_base64_decode("EgAAIgAAAAAkAAADSiAbAJcXvmFAAAAAAJiWgGhAAAAAAAAADGnUVkuWSoRawAAAAAAAAAAAAAAAAFVTRAAAAAAAadM7GNUzhfijGFUWwu2l3tuKxcZzIQN58Xz6D/11GBgVlL5p/poQRx1t4fQFXG0nRq/Wz4mInnRHMEUCIQDVXtGVP4YK3BvFzZk6u5J/SBVqyjHGRzeGX09P9tAVqAIgYwcE0r0JyOmfJgkMJfEbKPXZahNQRUQCws7ZKzn/26+BFGnTOxjVM4X4oxhVFsLtpd7bisXGgxRp0zsY1TOF+KMYVRbC7aXe24rFxvnqfAZjbGllbnR9B3J0MS4xLjHh8QESAfOxmXVi/XQrVNTr3qHWrqPUkGuPEAAAAAAAAAAAAAAAAAAAAAAAAAAA/wFLTpwG8kKWB097xI+SqXkWxtxeqQHdOcZQqW7aSDNOcMxKhbiy6FAs0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }

    #[test]
    fn test_decode_account_set_tx() {
        let raw_tx = simple_base64_decode("EgADIoAAAAAkAAAAFyAbAIaVU2hAAAAAAAAADHMhAviersdmezDzPQaHu6hsP+KgjMpAqRhsW94tqm+pejfYdEcwRQIhAL3gmh9mcEA/NBwhp3zzW6R+Rc3pdAluGqX8OYEdgmnnAiA9YCkbmifx3Kupz13tMHtPIyI+C28VaZHbYB37nEHOHHcKcmlwcGxlLmNvbYEUXnsRJSP2jS9eh5206sUcZpimkwQ=").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "12000322800000002400000017201B0086955368400000000000000C732102F89EAEC7667B30F33D0687BBA86C3FE2A08CCA40A9186C5BDE2DAA6FA97A37D874473045022100BDE09A1F6670403F341C21A77CF35BA47E45CDE974096E1AA5FC39811D8269E702203D60291B9A27F1DCABA9CF5DED307B4F23223E0B6F156991DB601DFB9C41CE1C770A726970706C652E636F6D81145E7B112523F68D2F5E879DB4EAC51C6698A69304");
    }

    #[test]
    fn test_encode_account_set_tx() {
        let raw_tx = simple_base64_decode("EgADIoAAAAAkAAAAFyAbAIaVU2hAAAAAAAAADHMhAviersdmezDzPQaHu6hsP+KgjMpAqRhsW94tqm+pejfYdEcwRQIhAL3gmh9mcEA/NBwhp3zzW6R+Rc3pdAluGqX8OYEdgmnnAiA9YCkbmifx3Kupz13tMHtPIyI+C28VaZHbYB37nEHOHHcKcmlwcGxlLmNvbYEUXnsRJSP2jS9eh5206sUcZpimkwQ=").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }

    #[test]
    fn test_decode_trust_set_tx() {
        // Example from https://github.com/sephynox/xrpl-rust/blob/0bb773469e17d10763c339f440fcc0c112cfcd4a/src/core/binarycodec/test_data/data-driven-tests.json
        let raw_tx = simple_base64_decode("EgAUIgACAAAkAAAALGPWQ41+pMaAAAAAAAAAAAAAAAAAAFdDRwAAAAAAgyKXvvWJ1Z+cA6hPkg+NkSjMHORoQAAAAAAAAAyBFL5sMHMq4zzyrzNEzoFyprkwAYPj").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let serialized = transaction.serialize().unwrap();

        assert_eq!(hex::encode(serialized).to_uppercase(), "1200142200020000240000002C63D6438D7EA4C680000000000000000000000000005743470000000000832297BEF589D59F9C03A84F920F8D9128CC1CE468400000000000000C8114BE6C30732AE33CF2AF3344CE8172A6B9300183E3");
    }

    #[test]
    fn test_encode_trust_set_tx() {
        let raw_tx = simple_base64_decode("EgAUIgACAAAkAAAALGPWQ41+pMaAAAAAAAAAAAAAAAAAAFdDRwAAAAAAgyKXvvWJ1Z+cA6hPkg+NkSjMHORoQAAAAAAAAAyBFL5sMHMq4zzyrzNEzoFyprkwAYPj").unwrap();

        let transaction = decode_factory(raw_tx.clone()).unwrap();

        let buff = transaction.serialize().unwrap();

        assert_eq!(hex::encode(raw_tx).to_uppercase(), hex::encode_upper(buff));
    }
}
