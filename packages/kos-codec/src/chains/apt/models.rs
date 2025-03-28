use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    #[serde(rename = "type")]
    pub r#type: String,
    pub hash: String,
    pub sender: String,
    #[serde(rename = "sequence_number")]
    pub sequence_number: String,
    #[serde(rename = "max_gas_amount")]
    pub max_gas_amount: String,
    #[serde(rename = "gas_unit_price")]
    pub gas_unit_price: String,
    #[serde(rename = "gas_currency_code")]
    pub gas_currency_code: String,
    #[serde(rename = "expiration_timestamp_secs")]
    pub expiration_timestamp_secs: String,
    pub payload: Option<Payload>,
    pub signature: Option<JSONSignature>,

    pub version: u64,
    #[serde(rename = "state_root_hash")]
    pub state_root_hash: String,
    #[serde(rename = "event_root_hash")]
    pub event_root_hash: String,
    #[serde(rename = "gas_used")]
    pub gas_used: u64,
    pub success: bool,
    #[serde(rename = "vm_status")]
    pub vm_status: String,
    #[serde(rename = "accumulator_root_hash")]
    pub accumulator_root_hash: String,

    pub timestamp: u64,

    pub id: String,
    pub round: u64,
    #[serde(rename = "previous_block_votes")]
    pub previous_block_votes: Vec<bool>,
    pub proposer: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Payload {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "type_arguments")]
    pub type_arguments: Vec<String>,
    pub arguments: Vec<serde_json::Value>,
    pub function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JSONSignature {
    #[serde(rename = "ed25519_signature")]
    ED25519(ED25519Signature),
    #[serde(rename = "multi_ed25519_signature")]
    MultiED25519(MultiED25519Signature),
    #[serde(rename = "multi_agent_signature")]
    MultiAgent(MultiAgentSignature),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ED25519Signature {
    #[serde(rename = "public_key")]
    pub public_key: String,
    #[serde(rename = "signature")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiED25519Signature {
    #[serde(rename = "public_keys")]
    pub public_keys: Vec<String>,
    #[serde(rename = "signatures")]
    pub signatures: Vec<String>,
    #[serde(rename = "threshold")]
    pub threshold: u8,
    #[serde(rename = "bitmap")]
    pub bitmap: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentSignature {
    #[serde(rename = "sender")]
    pub sender: JSONSigner,
    #[serde(rename = "secondary_signer_addresses")]
    pub secondary_signer_addresses: Vec<String>,
    #[serde(rename = "secondary_signers")]
    pub secondary_signers: Vec<JSONSigner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JSONSigner {
    #[serde(rename = "ed25519")]
    ED25519(ED25519Signature),
    #[serde(rename = "multi_ed25519")]
    MultiED25519(MultiED25519Signature),
}
