use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JSONSignature {
    #[serde(rename = "ed25519")]
    ED25519(ED25519Signature),
    #[serde(rename = "multi_ed25519")]
    MultiED25519(MultiED25519Signature),
    #[serde(rename = "multi_agent")]
    MultiAgent(MultiAgentSignature),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ED25519Signature {
    #[serde(rename = "public_key")]
    pub public_key: String,
    #[serde(rename = "signature")]
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiAgentSignature {
    #[serde(rename = "sender")]
    pub sender: JSONSigner,
    #[serde(rename = "secondary_signer_addresses")]
    pub secondary_signer_addresses: Vec<String>,
    #[serde(rename = "secondary_signers")]
    pub secondary_signers: Vec<JSONSigner>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JSONSigner {
    #[serde(rename = "ed25519")]
    ED25519(ED25519Signature),
    #[serde(rename = "multi_ed25519")]
    MultiED25519(MultiED25519Signature),
}
