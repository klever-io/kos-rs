use parity_scale_codec::{Compact, Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Transaction {
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "transactionVersion")]
    pub transaction_version: String,
    pub address: String,
    #[serde(rename = "assetId")]
    pub asset_id: Option<String>,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    pub era: String,
    #[serde(rename = "genesisHash")]
    pub genesis_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: Option<String>,
    pub method: String,
    pub mode: i64,
    pub nonce: String,
    #[serde(rename = "signedExtensions")]
    pub signed_extensions: Vec<String>,
    pub tip: String,
    pub version: i64,
    #[serde(rename = "withSignedTransaction")]
    pub with_signed_transaction: bool,
    pub signature: Option<String>,
}

impl Transaction {
    pub fn from_json(json_data: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_data)
    }
}

pub struct ExtrinsicPayload {
    method: Vec<u8>,
    nonce: u32,
    tip: u128,
    mode: u8,
    spec_version: u32,
    transaction_version: u32,
    genesis_hash: [u8; 32],
    block_hash: [u8; 32],
    metadata_hash: Vec<u8>,
    era: Vec<u8>,
}

impl ExtrinsicPayload {
    pub fn from_transaction(tx: &Transaction) -> Self {
        let spec_version = parse_hex_to_u32(&tx.spec_version);
        let transaction_version = parse_hex_to_u32(&tx.transaction_version);
        let nonce = parse_hex_to_u32(&tx.nonce);
        let tip = parse_hex_to_u128(&tx.tip);
        let mode = tx.mode.try_into().unwrap();
        let genesis_hash = parse_hex(&tx.genesis_hash).try_into().unwrap();
        let block_hash = parse_hex(&tx.block_hash).try_into().unwrap();
        let metadata_hash =
            parse_hex(&tx.metadata_hash.clone().unwrap_or_else(|| "00".to_string()));
        let era = parse_hex(&tx.era.clone());
        let method = hex::decode(tx.method.trim_start_matches("0x")).unwrap();

        ExtrinsicPayload {
            method,
            nonce,
            tip,
            mode,
            spec_version,
            transaction_version,
            genesis_hash,
            block_hash,
            metadata_hash,
            era,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.method.clone());
        bytes.extend(&self.era.clone());
        bytes.extend(Compact(self.nonce).encode());
        bytes.extend(Compact(self.tip).encode());
        bytes.extend(&self.mode.encode());
        bytes.extend(&self.spec_version.encode());
        bytes.extend(&self.transaction_version.encode());
        bytes.extend(&self.genesis_hash);
        bytes.extend(&self.block_hash);
        bytes.extend(&self.metadata_hash);

        bytes
    }
}

fn parse_hex_to_u32(hex_str: &str) -> u32 {
    u32::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap()
}

fn parse_hex_to_u128(hex_str: &str) -> u128 {
    u128::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap()
}

fn parse_hex(hex_str: &String) -> Vec<u8> {
    hex::decode(hex_str.trim_start_matches("0x")).unwrap()
}
