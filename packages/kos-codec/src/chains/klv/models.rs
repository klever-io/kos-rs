use crate::protos::generated::klv::proto;
use crate::protos::generated::klv::proto::tx_contract::ContractType;
use tiny_json_rs::mapper;
use tiny_json_rs::serializer;
use tiny_json_rs::Deserialize;
use tiny_json_rs::Serialize;

use crate::protos;
use kos::crypto::base64::simple_base64_decode;

#[derive(Serialize, Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq)]
pub struct Transaction {
    #[Rename = "RawData"]
    pub raw_data: Option<Raw>,
    #[Rename = "Signature"]
    pub signature: Option<Vec<String>>, //Base64 encoded
    #[Rename = "Result"]
    pub result: Option<i32>,
    #[Rename = "ResultCode"]
    pub result_code: Option<i32>,
    #[Rename = "Receipts"]
    pub receipts: Option<Vec<Receipt>>,
    #[Rename = "Block"]
    pub block: Option<u64>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Raw {
    #[Rename = "Nonce"]
    pub nonce: Option<u64>,
    #[Rename = "Sender"]
    pub sender: String,
    #[Rename = "Contract"]
    pub contract: Vec<TxContract>,
    #[Rename = "PermissionID"]
    pub permission_id: Option<i32>,
    #[Rename = "Data"]
    pub data: Option<Vec<String>>,
    #[Rename = "KAppFee"] // Use this to match the exact JSON field name for this field
    pub k_app_fee: Option<i64>,
    #[Rename = "BandwidthFee"] // Use this to match the exact JSON field name for this field
    pub bandwidth_fee: Option<i64>,
    #[Rename = "Version"]
    pub version: Option<u32>,
    #[Rename = "ChainID"]
    pub chain_id: String,
    #[Rename = "KDAFee"] // Use this to match the exact JSON field name for this field
    pub kda_fee: ::core::option::Option<KdaFee>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TxContract {
    #[Rename = "Parameter"]
    pub parameter: Parameter,
    #[Rename = "Type"]
    pub r#type: Option<i32>,
    // ... other fields
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Parameter {
    pub type_url: String,
    pub value: Option<String>,
    // ... other fields
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct KdaFee {
    #[Rename = "KDA"]
    pub kda: String,
    #[Rename = "Amount"]
    pub amount: i64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    #[Rename = "Data"]
    pub data: Vec<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ConversionError {
    InvalidData(&'static str),
    Base64Error,
    // You can add more error types as needed for detailed error handling
}

impl TryFrom<Transaction> for proto::Transaction {
    type Error = ConversionError;

    #[allow(clippy::needless_update)]
    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        let raw_data = match value.raw_data {
            Some(raw) => Some(proto::transaction::Raw::try_from(raw)?),
            None => None,
        };

        let receipts = value
            .receipts
            .unwrap_or_default()
            .into_iter()
            .map(proto::transaction::Receipt::try_from)
            .collect::<Result<_, _>>()?;

        let signatures = value
            .signature
            .unwrap_or_default()
            .into_iter()
            .map(|s| simple_base64_decode(&s).map_err(|_| ConversionError::Base64Error))
            .collect::<Result<Vec<_>, _>>()?;

        let proto_tx = proto::Transaction {
            raw_data,
            signature: signatures,
            result: value.result.unwrap_or(0),
            result_code: value.result_code.unwrap_or(0),
            receipts,
            block: value.block.unwrap_or(0),
            ..Default::default() // Include other fields as necessary
        };

        Ok(proto_tx)
    }
}

impl TryFrom<Raw> for proto::transaction::Raw {
    type Error = ConversionError;

    #[allow(clippy::needless_update)]
    fn try_from(value: Raw) -> Result<Self, Self::Error> {
        let contracts = value
            .contract
            .into_iter()
            .map(proto::TxContract::try_from)
            .collect::<Result<_, _>>()?;

        let chain_id_bytes =
            simple_base64_decode(&value.chain_id).map_err(|_| ConversionError::Base64Error)?;

        let datas = value
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|d| simple_base64_decode(&d).map_err(|_| ConversionError::Base64Error))
            .collect::<Result<Vec<_>, _>>()?;

        let proto_raw = proto::transaction::Raw {
            nonce: value.nonce.unwrap_or(0),
            sender: simple_base64_decode(&value.sender)
                .map_err(|_| ConversionError::Base64Error)?,
            contract: contracts,
            permission_id: value.permission_id.unwrap_or(0),
            data: datas,
            k_app_fee: value.k_app_fee.unwrap_or(0),
            bandwidth_fee: value.bandwidth_fee.unwrap_or(0),
            version: value.version.unwrap_or(0),
            chain_id: chain_id_bytes,
            kda_fee: value
                .kda_fee
                .map(proto::transaction::KdaFee::try_from)
                .transpose()?,
            ..Default::default()
        };

        Ok(proto_raw)
    }
}

impl TryFrom<TxContract> for proto::TxContract {
    type Error = ConversionError;

    fn try_from(value: TxContract) -> Result<Self, Self::Error> {
        // Remove escapes
        let contract_name = value.parameter.type_url.replace("\\", "");

        //Remove the "type.googleapis.com/" prefix
        let contract_name = contract_name
            .strip_prefix("type.googleapis.com/proto.")
            .ok_or(ConversionError::InvalidData("Invalid contract name"))?;
        //Add Type at the end of str
        let contract_name = format!("{contract_name}Type");
        let contract_type = ContractType::from_str_name(&contract_name)
            .ok_or(ConversionError::InvalidData("Invalid contract type"))?;
        let proto_contract = proto::TxContract {
            r#type: contract_type as i32,
            parameter: Option::from(protos::Any::try_from(value.parameter)?),
        };

        Ok(proto_contract)
    }
}

impl TryFrom<Parameter> for protos::Any {
    type Error = ConversionError;

    #[allow(clippy::needless_update)]
    fn try_from(value: Parameter) -> Result<Self, Self::Error> {
        let proto_parameter = protos::Any {
            type_url: value.type_url,
            value: simple_base64_decode(&value.value.unwrap_or_default())
                .map_err(|_| ConversionError::Base64Error)?,
            ..Default::default()
        };

        Ok(proto_parameter)
    }
}

impl TryFrom<KdaFee> for proto::transaction::KdaFee {
    type Error = ConversionError;

    #[allow(clippy::needless_update)]
    fn try_from(value: KdaFee) -> Result<Self, Self::Error> {
        let kda_bytes =
            simple_base64_decode(&value.kda).map_err(|_| ConversionError::Base64Error)?;

        let proto_kda_fee = proto::transaction::KdaFee {
            kda: kda_bytes,
            amount: value.amount,
            ..Default::default()
        };

        Ok(proto_kda_fee)
    }
}

impl TryFrom<Receipt> for proto::transaction::Receipt {
    type Error = ConversionError;

    #[allow(clippy::needless_update)]
    fn try_from(value: Receipt) -> Result<Self, Self::Error> {
        let data = value
            .data
            .into_iter()
            .map(|d| simple_base64_decode(&d).map_err(|_| ConversionError::Base64Error))
            .collect::<Result<_, _>>()?;

        let proto_receipt = proto::transaction::Receipt {
            data,
            ..Default::default()
        };

        Ok(proto_receipt)
    }
}
