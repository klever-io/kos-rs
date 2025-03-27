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
