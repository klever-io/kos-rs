pub mod account_set;
pub mod payment;
pub mod transaction_base;
pub mod trust_set;

use crate::chains::xrp::constants;
use crate::chains::ChainError;

use account_set::AccountSetTransaction;
use payment::PaymentTransaction;
use trust_set::TrustSetTransaction;
use xrpl::core::Parser;

use super::models;

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
            let fields = models::decode_transaction(tx.clone())?;
            let payment_transaction =
                PaymentTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(payment_transaction))
        }
        constants::TRANSACTION_TYPE_ACCOUNT_SET => {
            let fields = models::decode_transaction(tx.clone())?;
            let account_set_transaction =
                AccountSetTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(account_set_transaction))
        }
        constants::TRANSACTION_TYPE_TRUST_SET => {
            let fields = models::decode_transaction(tx.clone())?;
            let trust_set_transaction =
                TrustSetTransaction::from(fields).map_err(|_| ChainError::DecodeRawTx)?;
            Ok(Box::new(trust_set_transaction))
        }
        _ => Err(ChainError::InvalidData("invalid transaction".to_string())),
    }
}
