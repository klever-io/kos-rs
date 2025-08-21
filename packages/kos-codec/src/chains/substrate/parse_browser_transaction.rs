use kos::chains::ChainError;
use serde_json::{json, Value};
use subxt_core::metadata::Metadata;
use parity_scale_codec::Decode;

#[derive(Debug, Clone)]
pub struct CustomSubstrate {
    pub page: i32,
    pub page_limit: i32,
    pub order: String,
    pub order_field: String,
    pub stash_address: String,
    pub browser_transaction: BrowserTransaction,
}

#[derive(Debug, Clone)]
pub struct BrowserTransaction {
    pub spec_version: String,
    pub transaction_version: String,
    pub address: String,
    pub asset_id: String,
    pub block_hash: String,
    pub block_number: String,
    pub era: String,
    pub genesis_hash: String,
    pub metadata_hash: String,
    pub method: String,
    pub nonce: String,
    pub signed_extensions: Vec<String>,
    pub tip: String,
    pub version: u64,
    pub app_id: u64,
}

#[derive(Debug)]
pub struct TransactionResult {
    pub address: String,
    pub chain: String,
    pub raw_tx: Vec<u8>,
    pub specific: Vec<u8>,
}

pub struct Substrate {
    pub prefix: u8,
    pub chain_name: String,
}

fn load_metadata_from_hex(hex_string: &str) -> Result<Metadata, Box<dyn std::error::Error>> {
    let hex_clean = hex_string.strip_prefix("0x").unwrap_or(hex_string);
    let metadata_bytes = hex::decode(hex_clean)?;
    let metadata = Metadata::decode(&mut &metadata_bytes[..])?;
    Ok(metadata)
}

impl Substrate {
    pub fn new(prefix: u8, chain_name: String) -> Self {
        Self { prefix, chain_name }
    }

    pub async fn parse_browser_transaction(
        &self,
        call: &CustomSubstrate,
    ) -> Result<TransactionResult, ChainError> {
        let tx = &call.browser_transaction;

        let nonce = &tx.nonce;
        let tip = &tx.tip;
        let spec_version = &tx.spec_version;
        let transaction_version = &tx.transaction_version;

        let method_name = self.extract_method_name(&tx.method);
        let args = self.method_args(&method_name);

        let specific_data = json!({
            "call": tx.method,
            "method": method_name,
            "era": tx.era,
            "args": args,
            "nonce": nonce.to_string(),
            "tip": tip.to_string(),
            "blockHash": tx.block_hash,
            "genesisHash": tx.genesis_hash,
            "specVersion": spec_version.to_string(),
            "transactionVersion": transaction_version.to_string(),
            "signedExtensions": tx.signed_extensions
        });

        let specific_bytes = serde_json::to_vec(&specific_data)
            .unwrap()
            .try_into()
            .map_err(|e| {
                ChainError::InvalidData(format!("Failed to convert specific bytes: {}", e))
            })?;
        let raw_tx = self.build_raw_tx(tx, nonce, tip, spec_version, transaction_version);

        Ok(TransactionResult {
            address: tx.address.clone(),
            chain: self.chain_name.clone(),
            raw_tx,
            specific: specific_bytes,
        })
    }



    fn extract_method_name(&self, method_hex: &str) -> String {
        let hex_clean = method_hex.strip_prefix("0x").unwrap_or(method_hex);

        if hex_clean.len() < 4 {
            return "unknown".into();
        }

        let module_idx = u8::from_str_radix(&hex_clean[0..2], 16).unwrap_or(0);
        let method_idx = u8::from_str_radix(&hex_clean[2..4], 16).unwrap_or(0);

        match (module_idx, method_idx) {
            (4, 0) => "transfer",
            (4, 3) => "transfer_keep_alive",
            (6, 0) => "bond",
            (6, 1) => "bond_extra",
            (6, 2) => "unbond",
            (6, 5) => "nominate",
            (6, 16) => "claim_payout",
            (29, 1) => "join",
            (29, 4) => "claim_commission",
            (29, 5) => "set_claim_permission",
            _ => "unknown",
        }
        .into()
    }

    fn method_args(&self, method_name: &str) -> Value {
        match method_name {
            "transfer" | "transfer_keep_alive" => json!({
                "dest": "destination_address",
                "value": "amount"
            }),
            "bond" => json!({
                "controller": "controller_address",
                "value": "bond_amount",
                "payee": "reward_destination"
            }),
            "bond_extra" => json!({
                "max_additional": "additional_amount"
            }),
            "unbond" => json!({
                "value": "unbond_amount"
            }),
            "nominate" => json!({
                "targets": []
            }),
            _ => json!({}),
        }
    }

    fn build_raw_tx(
        &self,
        tx: &BrowserTransaction,
        nonce: &String,
        tip: &String,
        spec_version: &String,
        transaction_version: &String,
    ) -> Vec<u8> {
        let mut raw_data = Vec::new();

        raw_data.extend_from_slice(&nonce.as_bytes());
        raw_data.extend_from_slice(&tip.as_bytes());
        raw_data.extend_from_slice(&spec_version.as_bytes());
        raw_data.extend_from_slice(&transaction_version.as_bytes());

        if let Ok(method_bytes) = hex::decode(tx.method.strip_prefix("0x").unwrap_or(&tx.method)) {
            raw_data.extend_from_slice(&method_bytes);
        }

        raw_data
    }
}

pub async fn parse_substrate_transaction(
    substrate: &Substrate,
    call: &CustomSubstrate,
) -> Result<TransactionResult, ChainError> {
    substrate.parse_browser_transaction(call).await
}

#[cfg(test)]
mod test {
    #[test]
    fn test_load_metadata_from_hex() {
        let hex_string = "0x1234567890abcdef";
        let result = super::load_metadata_from_hex(hex_string);
        assert!(result.is_ok());
    }
}