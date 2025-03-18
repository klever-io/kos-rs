pub mod payment;
pub mod transaction_base;

use xrpl::core::Parser;

use crate::chains::xrp::constants;
use crate::chains::xrp::transactions;
use crate::chains::ChainError;

pub trait Serialize {
    /// Serialize the object
    fn serialize(&self) -> Result<Vec<u8>, ChainError>;
}

pub trait Transaction: Serialize {
    // fn common(&self) -> &transaction_base::TransactionCommon;
    fn common_mut(&mut self) -> &mut transaction_base::TransactionCommon;
}
// pub trait DecodeTransactionFactory {
//     fn decode(tx: Vec<u8>) -> Result<Box<dyn Transaction>, ChainError>;
// }

// impl DecodeTransactionFactory {
//    fn decode(tx: Vec<u8>) -> Result<Box<dyn Transaction>, ChainError> {}
// }

pub fn decode_factory(tx: Vec<u8>) -> Result<Box<dyn Transaction>, ChainError> {
    let mut binary_parser = xrpl::core::BinaryParser::from(tx.clone());
    let field_info = binary_parser.read_field().unwrap();
    if field_info.name != "TransactionType" {
        return Err(ChainError::InvalidData(
            "invalid transaction TransactionType".to_string(),
        ));
    }

    let transaction_type: u16 = binary_parser.read_uint16().unwrap();

    match transaction_type {
        constants::TRANSACTION_TYPE_PAYMENT => {
            let payment_transaction =
                transactions::payment::decode_payment_transaction(tx.clone().as_ref()).unwrap();
            Ok(Box::new(payment_transaction))
        }
        _ => Err(ChainError::InvalidData("invalid transaction".to_string())),
    }
}
