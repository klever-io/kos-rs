use alloc::string::String;
use tiny_json_rs::Deserialize;
use tiny_json_rs::Serialize;

#[derive(Serialize, Deserialize)]
pub struct AptosSignature {
    #[Rename = "Type"]
    pub r#type: String,
    #[Rename = "PublicKey"]
    pub public_key: String,
    #[Rename = "Signature"]
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
struct AptosTransaction {
    #[Rename = "Signature"]
    signature: Option<AptosSignature>,
}

#[derive(Serialize, Deserialize)]
struct TxSpecific {
    #[Rename = "SigningMessage"]
    signing_message: String,
    #[Rename = "Transaction"]
    transaction: AptosTransaction,
}
