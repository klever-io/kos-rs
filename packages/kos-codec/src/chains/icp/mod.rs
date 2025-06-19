use base32;
use base64;
use kos::chains::util::{byte_vectors_to_bytes, bytes_to_byte_vectors};
use kos::chains::{ChainError, Transaction};
use kos::crypto::base64::simple_base64_decode;
use leb128;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_json_rs::serializer;

#[derive(Debug, Clone)]
enum TransactionType {
    Regular,
    DAppCall,
}

// Structure for DApp requests (ICRC-49)
#[derive(Debug, Deserialize)]
pub struct DAppRequest {
    pub id: Option<u64>,
    pub jsonrpc: String,
    pub method: String,
    pub params: ICRC49Params,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ICRC49Params {
    pub canister_id: String,
    pub sender: String,
    pub method: String,
    pub arg: String,           // Base64 encoded
    pub nonce: Option<String>, // Opcional
}

#[derive(Debug, Serialize)]
pub struct DAppResponse {
    pub id: Option<u64>,
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<DAppResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DAppError>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum DAppResult {
    CallResult(String),
    Success(bool),
}

#[derive(Debug, Serialize)]
pub struct DAppError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallContentRequest {
    #[serde(rename = "request_type")]
    pub request_type: String,
    #[serde(rename = "canister_id")]
    pub canister_id: Vec<u8>,
    #[serde(rename = "method_name")]
    pub method_name: String,
    #[serde(rename = "arg")]
    pub arg: Vec<u8>,
    #[serde(rename = "sender")]
    pub sender: Vec<u8>,
    #[serde(rename = "ingress_expiry")]
    pub ingress_expiry: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum HashValue {
    String(String),
    Bytes(Vec<u8>),
    UInt64(u64),
    Int64(i64),
    Int(i32),
    ByteArrays(Vec<Vec<u8>>),
    Values(Vec<HashValue>),
}

const TABLE_0: [u32; 256] = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
];

pub fn crc_calc_singletable(buffer: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;

    for &byte in buffer.iter() {
        crc = TABLE_0[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }

    !crc
}

#[derive(Debug, Deserialize)]
struct MethodCheck {
    method: String,
}

fn detect_transaction_type(raw_data: &[u8]) -> TransactionType {
    if let Ok(json_str) = std::str::from_utf8(raw_data) {
        if let Ok(method_check) = serde_json::from_str::<MethodCheck>(json_str) {
            if method_check.method == "icrc49_call_canister" {
                return TransactionType::DAppCall;
            }
        }
    }
    TransactionType::Regular
}

// Main function for encoding transactions for signing
// Automatically detects if it's a regular transaction or DApp ICRC-49
pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let transaction_type = detect_transaction_type(&transaction.raw_data);

    match transaction_type {
        TransactionType::Regular => {
            // Original behavior for regular ICP transactions
            encode_regular_transaction_for_sign(transaction)
        }
        TransactionType::DAppCall => {
            // New behavior for DApp ICRC-49 transactions
            encode_dapp_transaction_for_sign(transaction)
        }
    }
}

// Main function for encoding transactions for broadcast
// Automatically detects if it's a regular transaction or DApp ICRC-49
pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let transaction_type = detect_transaction_type(&transaction.raw_data);

    match transaction_type {
        TransactionType::Regular => {
            // Original behavior for regular ICP transactions
            encode_regular_transaction_for_broadcast(transaction)
        }
        TransactionType::DAppCall => {
            // For DApp transactions, prepare ICRC response
            encode_dapp_transaction_for_broadcast(transaction)
        }
    }
}

fn encode_regular_transaction_for_sign(
    mut transaction: Transaction,
) -> Result<Transaction, ChainError> {
    let hex = hex::decode(transaction.raw_data.clone()).map_err(|_| ChainError::DecodeRawTx)?;
    let raw_data_str = String::from_utf8(hex).map_err(|_| ChainError::DecodeRawTx)?;

    let wrapped_data = format!("{{\"hashes\":{}}}", raw_data_str);

    #[derive(tiny_json_rs::Deserialize)]
    struct HashContainer {
        hashes: Vec<String>,
    }

    let container: HashContainer =
        tiny_json_rs::decode(wrapped_data).map_err(|_| ChainError::DecodeHash)?;

    let icp_hashes = container.hashes;
    let mut hashes = Vec::new();

    for hash_hex in icp_hashes {
        hashes.push(hex::decode(hash_hex).unwrap());
    }

    transaction.tx_hash = byte_vectors_to_bytes(&hashes);
    Ok(transaction)
}

fn encode_regular_transaction_for_broadcast(
    mut transaction: Transaction,
) -> Result<Transaction, ChainError> {
    let signatures = bytes_to_byte_vectors(transaction.signature)?;

    let mut signatures_vec = Vec::new();
    for signature in signatures {
        signatures_vec.push(hex::encode(signature));
    }

    let signatures_json = tiny_json_rs::encode(signatures_vec);
    transaction.signature = signatures_json.into_bytes();
    Ok(transaction)
}

fn encode_dapp_transaction_for_sign(
    mut transaction: Transaction,
) -> Result<Transaction, ChainError> {
    // Parse DApp JSON request
    let dapp_request: DAppRequest = serde_json::from_slice(&transaction.raw_data).map_err(|e| {
        ChainError::InvalidTransaction(format!("Failed to parse DApp request: {}", e))
    })?;

    // Check if it's an ICRC-49 request
    if dapp_request.method != "icrc49_call_canister" {
        return Err(ChainError::InvalidTransaction(format!(
            "Unsupported method: {}",
            dapp_request.method
        )));
    }

    // Convert to CallContentRequest (internal IC format)
    let call_request = create_call_request_from_dapp(dapp_request.params)?;

    // **IMPORTANT: Encode in CBOR for IC communication**
    let cbor_content = encode_call_content_to_cbor(&call_request)?;

    // Calculate request hash for signing
    let request_hash = calculate_call_request_hash(&call_request)?;

    // Store the hash that will be signed
    transaction.tx_hash = request_hash;

    // Store the CBOR request for later sending to IC
    transaction.raw_data = cbor_content;

    Ok(transaction)
}

// Prepare ICRC-49 response for broadcast (sending to IC)
fn encode_dapp_transaction_for_broadcast(
    mut transaction: Transaction,
) -> Result<Transaction, ChainError> {
    // For DApp transactions, raw_data already contains the CBOR to send to IC
    // The signature must be applied to the CBOR authentication envelope

    // Create CBOR authentication envelope with signature
    let auth_envelope = create_cbor_auth_envelope(&transaction)?;

    // The final result is the complete CBOR envelope ready to send to IC
    transaction.signature = auth_envelope;

    Ok(transaction)
}

// Encode call content in CBOR format for IC
fn encode_call_content_to_cbor(call_request: &CallContentRequest) -> Result<Vec<u8>, ChainError> {
    let mut content_map = BTreeMap::new();

    // Required fields for canister call
    content_map.insert(
        CborValue::Text("request_type".to_string()),
        CborValue::Text(call_request.request_type.clone()),
    );
    content_map.insert(
        CborValue::Text("canister_id".to_string()),
        CborValue::Bytes(call_request.canister_id.clone()),
    );
    content_map.insert(
        CborValue::Text("method_name".to_string()),
        CborValue::Text(call_request.method_name.clone()),
    );
    content_map.insert(
        CborValue::Text("arg".to_string()),
        CborValue::Bytes(call_request.arg.clone()),
    );
    content_map.insert(
        CborValue::Text("sender".to_string()),
        CborValue::Bytes(call_request.sender.clone()),
    );
    content_map.insert(
        CborValue::Text("ingress_expiry".to_string()),
        CborValue::Integer(call_request.ingress_expiry as i128),
    );

    // Add nonce if present
    if let Some(nonce) = &call_request.nonce {
        content_map.insert(
            CborValue::Text("nonce".to_string()),
            CborValue::Bytes(nonce.clone()),
        );
    }

    let cbor_content = CborValue::Map(content_map);

    // Encode to CBOR bytes
    let mut cbor_bytes = Vec::new();
    serde_cbor::to_writer(&mut cbor_bytes, &cbor_content)
        .map_err(|e| ChainError::InvalidData(format!("CBOR encoding failed: {}", e)))?;

    Ok(cbor_bytes)
}

// Create CBOR authentication envelope with signature
fn create_cbor_auth_envelope(transaction: &Transaction) -> Result<Vec<u8>, ChainError> {
    use serde_cbor::Value as CborValue;
    use std::collections::BTreeMap;

    // Create authentication envelope according to IC spec
    let mut envelope = BTreeMap::new();

    // Call content (already in CBOR)
    envelope.insert(
        CborValue::Text("content".to_string()),
        CborValue::Bytes(transaction.raw_data.clone()),
    );

    // Wallet signature
    if !transaction.signature.is_empty() {
        envelope.insert(
            CborValue::Text("sender_sig".to_string()),
            CborValue::Bytes(transaction.signature.clone()),
        );
    }

    // Public key of sender (you can implement according to your wallet)
    // envelope.insert("sender_pubkey", CborValue::Bytes(public_key));

    let cbor_envelope = CborValue::Map(envelope);

    // Encode complete envelope
    let mut envelope_bytes = Vec::new();
    serde_cbor::to_writer(&mut envelope_bytes, &cbor_envelope)
        .map_err(|e| ChainError::InvalidData(format!("CBOR envelope encoding failed: {}", e)))?;

    Ok(envelope_bytes)
}

// Decode CBOR response from IC
pub fn decode_ic_response(cbor_data: &[u8]) -> Result<ICResponse, ChainError> {
    use serde_cbor::Value as CborValue;

    let cbor_value: CborValue = serde_cbor::from_slice(cbor_data)
        .map_err(|e| ChainError::InvalidData(format!("CBOR decode failed: {}", e)))?;

    match cbor_value {
        CborValue::Map(map) => {
            let status = map
                .get(&CborValue::Text("status".to_string()))
                .and_then(|v| match v {
                    CborValue::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "unknown".to_string());

            let reply = map
                .get(&CborValue::Text("reply".to_string()))
                .and_then(|v| match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                });

            let reject_code = map
                .get(&CborValue::Text("reject_code".to_string()))
                .and_then(|v| match v {
                    CborValue::Integer(i) => Some(*i as u64),
                    _ => None,
                });

            let reject_message = map
                .get(&CborValue::Text("reject_message".to_string()))
                .and_then(|v| match v {
                    CborValue::Text(s) => Some(s.clone()),
                    _ => None,
                });

            Ok(ICResponse {
                status,
                reply,
                reject_code,
                reject_message,
            })
        }
        _ => Err(ChainError::InvalidData(
            "Invalid CBOR response format".to_string(),
        )),
    }
}

// IC response structure
#[derive(Debug)]
pub struct ICResponse {
    pub status: String,
    pub reply: Option<Vec<u8>>,
    pub reject_code: Option<u64>,
    pub reject_message: Option<String>,
}

// Create complete CBOR request for sending to IC
pub fn create_ic_request_cbor(
    call_request: &CallContentRequest,
    signature: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, ChainError> {
    use serde_cbor::Value as CborValue;
    use std::collections::BTreeMap;

    // First, create the call content
    let content_cbor = encode_call_content_to_cbor(call_request)?;

    // Create complete authentication envelope
    let mut envelope = BTreeMap::new();

    // Request content
    envelope.insert(
        CborValue::Text("content".to_string()),
        CborValue::Bytes(content_cbor),
    );

    // Authentication information
    let mut sender_sig = BTreeMap::new();
    sender_sig.insert(
        CborValue::Text("signature".to_string()),
        CborValue::Bytes(signature.to_vec()),
    );
    sender_sig.insert(
        CborValue::Text("public_key".to_string()),
        CborValue::Bytes(public_key.to_vec()),
    );

    envelope.insert(
        CborValue::Text("sender_sig".to_string()),
        CborValue::Map(sender_sig),
    );

    // Tag CBOR 55799 to identify as IC CBOR data
    let tagged_envelope = CborValue::Tag(55799, Box::new(CborValue::Map(envelope)));

    // Encode to bytes
    let mut request_bytes = Vec::new();
    serde_cbor::to_writer(&mut request_bytes, &tagged_envelope)
        .map_err(|e| ChainError::InvalidData(format!("Final CBOR encoding failed: {}", e)))?;

    Ok(request_bytes)
}

// Create a CallContentRequest from DApp parameters
fn create_call_request_from_dapp(params: ICRC49Params) -> Result<CallContentRequest, ChainError> {
    // Convert canister_id from string to bytes
    let canister_bytes = principal_to_bytes(&params.canister_id)?;

    // Convert sender from string to bytes
    let sender_bytes = principal_to_bytes(&params.sender)?;

    // Decode arguments from base64
    let arg_bytes = simple_base64_decode(&params.arg)
        .map_err(|e| ChainError::InvalidData(format!("Failed to decode arg: {}", e)))?;

    // Calculate expiration time (4 minutes)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ChainError::InvalidData(format!("Time error: {}", e)))?;

    let created_at = now.as_nanos() as i64;
    let expire_time: i64 = 240_000_000_000; // 4 minutes in nanoseconds
    let ingress_expiry = (created_at + expire_time) as u64;

    // Process optional nonce
    let nonce_bytes = if let Some(nonce_str) = params.nonce {
        Some(
            simple_base64_decode(&nonce_str)
                .map_err(|e| ChainError::InvalidData(format!("Failed to decode nonce: {}", e)))?,
        )
    } else {
        None
    };

    Ok(CallContentRequest {
        request_type: "call".to_string(),
        canister_id: canister_bytes,
        method_name: params.method,
        arg: arg_bytes,
        sender: sender_bytes,
        ingress_expiry,
        nonce: nonce_bytes,
    })
}

fn calculate_call_request_hash(call_request: &CallContentRequest) -> Result<Vec<u8>, ChainError> {
    let mut request = HashMap::new();

    request.insert(
        "request_type".to_string(),
        HashValue::String(call_request.request_type.clone()),
    );
    request.insert(
        "canister_id".to_string(),
        HashValue::Bytes(call_request.canister_id.clone()),
    );
    request.insert(
        "method_name".to_string(),
        HashValue::String(call_request.method_name.clone()),
    );
    request.insert(
        "arg".to_string(),
        HashValue::Bytes(call_request.arg.clone()),
    );
    request.insert(
        "sender".to_string(),
        HashValue::Bytes(call_request.sender.clone()),
    );
    request.insert(
        "ingress_expiry".to_string(),
        HashValue::UInt64(call_request.ingress_expiry),
    );

    // Add nonce if present
    if let Some(nonce) = &call_request.nonce {
        request.insert("nonce".to_string(), HashValue::Bytes(nonce.clone()));
    }

    calculate_payload_hash(request)
}

fn principal_to_bytes(principal_str: &str) -> Result<Vec<u8>, ChainError> {
    let str32 = principal_str.replace("-", "").to_uppercase();

    let envelope = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &str32)
        .ok_or_else(|| ChainError::InvalidData("Invalid base32 encoding".to_string()))?;

    if envelope.len() < 4 {
        return Err(ChainError::InvalidAccountLength);
    }

    // Verify checksum
    let expected = u32::from_be_bytes([envelope[0], envelope[1], envelope[2], envelope[3]]);
    let data = &envelope[4..];
    let actual = crc_calc_singletable(data);

    if expected != actual {
        return Err(ChainError::InvalidAccountLength);
    }

    Ok(data.to_vec())
}

fn sort_byte_arrays(src: &mut Vec<Vec<u8>>) {
    src.sort_by(|a, b| a.cmp(b));
}

fn hash_value(value: &HashValue) -> Result<Vec<u8>, ChainError> {
    let hash = match value {
        HashValue::String(s) => {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            hasher.finalize().to_vec()
        }
        HashValue::Bytes(b) => {
            let mut hasher = Sha256::new();
            hasher.update(b);
            hasher.finalize().to_vec()
        }
        HashValue::UInt64(n) => {
            let mut buf = Vec::new();
            leb128::write::signed(&mut buf, *n as i64)
                .map_err(|e| ChainError::InvalidData(e.to_string()))?;
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            hasher.finalize().to_vec()
        }
        HashValue::Int64(n) => {
            let mut buf = Vec::new();
            leb128::write::signed(&mut buf, *n)
                .map_err(|e| ChainError::InvalidData(e.to_string()))?;
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            hasher.finalize().to_vec()
        }
        HashValue::Int(n) => {
            let mut buf = Vec::new();
            leb128::write::signed(&mut buf, *n as i64)
                .map_err(|e| ChainError::InvalidData(e.to_string()))?;
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            hasher.finalize().to_vec()
        }
        HashValue::ByteArrays(arrays) => {
            let mut aux_hash = Vec::new();
            for elem in arrays {
                let h = hash_value(&HashValue::Bytes(elem.clone()))?;
                aux_hash.extend_from_slice(&h);
            }
            let mut hasher = Sha256::new();
            hasher.update(&aux_hash);
            hasher.finalize().to_vec()
        }
        HashValue::Values(values) => {
            let mut aux_hash = Vec::new();
            for elem in values {
                let h = hash_value(elem)?;
                aux_hash.extend_from_slice(&h);
            }
            let mut hasher = Sha256::new();
            hasher.update(&aux_hash);
            hasher.finalize().to_vec()
        }
    };

    Ok(hash)
}

fn calculate_payload_hash(request: HashMap<String, HashValue>) -> Result<Vec<u8>, ChainError> {
    let mut concatenated_request_hash = Vec::new();

    for (key, value) in request {
        let mut key_hasher = Sha256::new();
        key_hasher.update(key.as_bytes());
        let key_hash = key_hasher.finalize();

        let value_hash = hash_value(&value)?;

        let mut combined = key_hash.to_vec();
        combined.extend_from_slice(&value_hash);
        concatenated_request_hash.push(combined);
    }

    sort_byte_arrays(&mut concatenated_request_hash);

    let mut concatenated_hash = Vec::new();
    for hash in concatenated_request_hash {
        concatenated_hash.extend_from_slice(&hash);
    }

    let mut final_hasher = Sha256::new();
    final_hasher.update(&concatenated_hash);
    let hash = final_hasher.finalize();

    let mut result = b"\x0Aic-request".to_vec();
    result.extend_from_slice(&hash);
    Ok(result)
}

// Create ICRC-49 error response
pub fn create_error_response(request_id: Option<u64>, code: i32, message: String) -> Vec<u8> {
    let response = DAppResponse {
        id: request_id,
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(DAppError { code, message }),
    };

    serde_json::to_vec(&response).unwrap_or_default()
}

// Validate if an ICRC-49 request is valid
pub fn validate_icrc49_request(raw_data: &[u8]) -> Result<DAppRequest, ChainError> {
    let request: DAppRequest = serde_json::from_slice(raw_data)
        .map_err(|e| ChainError::InvalidTransaction(format!("Invalid JSON: {}", e)))?;

    // Basic validations
    if request.jsonrpc != "2.0" {
        return Err(ChainError::InvalidTransaction(
            "Invalid JSON-RPC version".to_string(),
        ));
    }

    if request.method != "icrc49_call_canister" {
        return Err(ChainError::InvalidTransaction(format!(
            "Unsupported method: {}",
            request.method
        )));
    }

    // Validate required fields
    if request.params.canister_id.is_empty() {
        return Err(ChainError::InvalidTransaction(
            "canisterId is required".to_string(),
        ));
    }

    if request.params.sender.is_empty() {
        return Err(ChainError::InvalidTransaction(
            "sender is required".to_string(),
        ));
    }

    if request.params.method.is_empty() {
        return Err(ChainError::InvalidTransaction(
            "method is required".to_string(),
        ));
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_encoding() {
        let call_request = CallContentRequest {
            request_type: "call".to_string(),
            canister_id: vec![0x01, 0x02, 0x03],
            method_name: "test_method".to_string(),
            arg: vec![0x04, 0x05, 0x06],
            sender: vec![0x07, 0x08, 0x09],
            ingress_expiry: 1234567890,
            nonce: Some(vec![0x0a, 0x0b]),
        };

        let cbor_result = encode_call_content_to_cbor(&call_request);
        assert!(cbor_result.is_ok(), "CBOR encoding should succeed");

        let cbor_bytes = cbor_result.unwrap();
        assert!(!cbor_bytes.is_empty(), "CBOR bytes should not be empty");

        // Verify if it contains the correct CBOR tag
        // The first bytes should indicate a CBOR map
        assert!(
            cbor_bytes[0] & 0xE0 == 0xA0,
            "Should start with CBOR map marker"
        );
    }

    #[test]
    fn test_ic_request_creation() {
        let call_request = CallContentRequest {
            request_type: "call".to_string(),
            canister_id: vec![0x01, 0x02, 0x03],
            method_name: "test".to_string(),
            arg: vec![0x04, 0x05],
            sender: vec![0x06, 0x07],
            ingress_expiry: 1000000000,
            nonce: None,
        };

        let signature = vec![0x11, 0x22, 0x33];
        let public_key = vec![0x44, 0x55, 0x66];

        let ic_request = create_ic_request_cbor(&call_request, &signature, &public_key);
        assert!(ic_request.is_ok(), "IC request creation should succeed");

        let request_bytes = ic_request.unwrap();
        assert!(
            !request_bytes.is_empty(),
            "Request bytes should not be empty"
        );
    }

    #[test]
    fn test_transaction_type_detection() {
        // Test for DApp ICRC-49 transaction
        let dapp_request = r#"{"method": "icrc49_call_canister", "params": {}}"#.as_bytes();
        assert!(matches!(
            detect_transaction_type(dapp_request),
            TransactionType::DAppCall
        ));

        // Test for regular transaction (hex data)
        let regular_tx = "48656c6c6f20576f726c64".as_bytes();
        assert!(matches!(
            detect_transaction_type(regular_tx),
            TransactionType::Regular
        ));

        // Test for JSON that is not DApp
        let other_json = r#"{"method": "other_method", "data": "test"}"#.as_bytes();
        assert!(matches!(
            detect_transaction_type(other_json),
            TransactionType::Regular
        ));
    }

    #[test]
    fn test_icrc49_request_validation() {
        // Test for valid request
        let valid_request = r#"{
            "id": 1,
            "jsonrpc": "2.0",
            "method": "icrc49_call_canister",
            "params": {
                "canisterId": "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "sender": "sgyks-q7tq3-tczsp-tytog-mxwxi-qxnym-sfoh6-ky4rj-dxhls-ryvy7-zae",
                "method": "greet",
                "arg": "RElETAABcQJtZQ=="
            }
        }"#;

        let result = validate_icrc49_request(valid_request.as_bytes());
        assert!(result.is_ok());

        // Test for invalid request (wrong method)
        let invalid_request = r#"{
            "id": 1,
            "jsonrpc": "2.0",
            "method": "invalid_method",
            "params": {}
        }"#;

        let result = validate_icrc49_request(invalid_request.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_principal_to_bytes() {
        // Test with valid principal
        let principal = "rrkah-fqaaa-aaaaa-aaaaq-cai";
        let result = principal_to_bytes(principal);
        assert!(result.is_ok());

        // Test with invalid principal
        let invalid_principal = "invalid-principal";
        let result = principal_to_bytes(invalid_principal);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_response_creation() {
        let error_response =
            create_error_response(Some(1), 3000, "Permission not granted".to_string());

        let response_json: serde_json::Value =
            serde_json::from_slice(&error_response).expect("Error response should be valid JSON");

        assert_eq!(response_json["id"], 1);
        assert_eq!(response_json["jsonrpc"], "2.0");
        assert_eq!(response_json["error"]["code"], 3000);
        assert_eq!(response_json["error"]["message"], "Permission not granted");
    }

    #[test]
    fn test_regular_transaction_compatibility() {
        // Test to ensure regular transactions still work
        let regular_data = "7b2268617368657322317d"; // JSON {"hashes":["hash1"]} in hex

        let mut transaction = Transaction {
            raw_data: regular_data.as_bytes().to_vec(),
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        // Should detect as regular transaction
        assert!(matches!(
            detect_transaction_type(&transaction.raw_data),
            TransactionType::Regular
        ));
    }
}
