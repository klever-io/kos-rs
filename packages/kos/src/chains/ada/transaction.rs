use hex;
use std::error::Error;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TxBody {
    // TBody
}

impl TxBody {
    fn hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct VKeyWitness {
    pub v_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct WitnessSet {
    pub v_key_witness_set: Vec<VKeyWitness>,
}

pub struct Tx {
    pub body: Option<TxBody>,
    pub witness_set: WitnessSet,
    pub is_valid: bool,
    pub auxiliary_data: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaOperationIdentifier {
    pub index: i32,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaAccount {
    pub address: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaCoinIdentifier {
    pub identifier: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaCoinChange {
    pub coin_identifier: RosettaCoinIdentifier,
    pub coin_action: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaBalance {
    pub value: String,
    pub currency: RosettaCurrency,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaCurrency {
    pub symbol: String,
    pub decimals: u8,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaOperation {
    pub operation_identifier: RosettaOperationIdentifier,
    #[serde(rename = "type")]
    pub operation_type: String,
    pub status: String,
    pub account: RosettaAccount,
    pub amount: RosettaBalance,
    pub coin_change: RosettaCoinChange,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaTransactionOperations {
    pub operations: Vec<RosettaOperation>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RosettaTransaction(pub String, pub RosettaTransactionOperations);
