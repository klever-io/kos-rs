use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
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
}

impl Transaction {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let tx = match serde_json::from_slice(&bytes) {
            Ok(tx) => tx,
            Err(e) => return Err(format!("Error deserializing transaction: {}", e)),
        };
        Ok(tx)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = match serde_json::to_vec(&self) {
            Ok(bytes) => bytes,
            Err(e) => return Err(format!("Error serializing transaction: {}", e)),
        };
        Ok(bytes)
    }
}
