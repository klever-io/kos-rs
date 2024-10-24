use parity_scale_codec::{Compact, Decode, Encode};
use serde::{Deserialize, Serialize};
use subxt::utils::Era;

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
    spec_version: u32,
    transaction_version: u32,
    genesis_hash: [u8; 32],
    block_hash: [u8; 32],
    era: Era,
}

impl ExtrinsicPayload {
    pub fn from_transaction(tx: &Transaction) -> Self {
        let spec_version =
            u32::from_str_radix(tx.spec_version.trim_start_matches("0x"), 16).unwrap();
        let transaction_version =
            u32::from_str_radix(tx.transaction_version.trim_start_matches("0x"), 16).unwrap();
        let nonce = u32::from_str_radix(tx.nonce.trim_start_matches("0x"), 16).unwrap();
        let tip = u128::from_str_radix(tx.tip.trim_start_matches("0x"), 16).unwrap();
        let genesis_hash = hex::decode(tx.genesis_hash.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let block_hash = hex::decode(tx.block_hash.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();

        let era = Era::decode(
            &mut hex::decode(tx.era.trim_start_matches("0x"))
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let method = hex::decode(tx.method.trim_start_matches("0x")).unwrap();

        ExtrinsicPayload {
            method,
            nonce,
            tip,
            spec_version,
            transaction_version,
            genesis_hash,
            block_hash,
            era,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.method.clone());
        bytes.extend(&self.era.encode());
        bytes.extend(Compact(self.nonce).encode());
        bytes.extend(Compact(self.tip).encode());
        // Encode mode
        bytes.extend(&[0]);
        bytes.extend(&self.spec_version.encode());
        bytes.extend(&self.transaction_version.encode());
        bytes.extend(&self.genesis_hash);
        bytes.extend(&self.block_hash);
        // Encode metadata_hash
        bytes.extend(&[0]);

        bytes
    }
}
