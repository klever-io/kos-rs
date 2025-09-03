use base32;
use kos::chains::icp::crc_calc_singletable;
use kos::chains::util::{byte_vectors_to_bytes, bytes_to_byte_vectors};
use kos::chains::{ChainError, Transaction};
use kos::crypto::base64::{simple_base64_decode, simple_base64_encode};
use leb128;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
enum TransactionType {
    Regular,
    DAppCall,
}

// Structure for DApp requests (ICRC-49)
#[derive(Debug, Deserialize)]
pub struct DAppRequest {
    #[allow(dead_code)]
    pub id: Option<u64>,
    #[allow(dead_code)]
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
pub struct DAppResult {
    #[serde(rename = "contentMap")]
    pub content_map: String,
    pub certificate: String,
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
#[allow(dead_code)]
pub enum HashValue {
    String(String),
    Bytes(Vec<u8>),
    UInt64(u64),
    Int64(i64),
    Int(i32),
    ByteArrays(Vec<Vec<u8>>),
    Values(Vec<HashValue>),
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
pub fn encode_for_sign(transaction: Transaction) -> Result<Transaction, ChainError> {
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
pub fn encode_for_broadcast(transaction: Transaction) -> Result<Transaction, ChainError> {
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

    let wrapped_data = format!("{{\"hashes\":{raw_data_str}}}");

    #[derive(Deserialize)]
    struct HashContainer {
        hashes: Vec<String>,
    }

    let container: HashContainer =
        serde_json::from_str(&wrapped_data).map_err(|_| ChainError::DecodeHash)?;
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

    let signatures_json = serde_json::to_string(&signatures_vec)
        .map_err(|_| ChainError::InvalidData("Failed to serialize signatures".to_string()))?;
    transaction.signature = signatures_json.into_bytes();
    Ok(transaction)
}

fn encode_dapp_transaction_for_sign(
    mut transaction: Transaction,
) -> Result<Transaction, ChainError> {
    // Parse DApp JSON request
    let dapp_request: DAppRequest = serde_json::from_slice(&transaction.raw_data).map_err(|e| {
        ChainError::InvalidTransaction(format!("Failed to parse DApp request: {e}"))
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

    // Encode in CBOR for IC communication
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
    // The raw_data already contains the CBOR content to send to IC
    let content_map_base64 = simple_base64_encode(&transaction.raw_data);

    // For DApp transactions, initially the certificate is empty
    // The dApp will make the call to IC and receive the certificate
    let certificate_base64 = String::new();

    // Create response in the format expected by the dApp
    let dapp_result = DAppResult {
        content_map: content_map_base64,
        certificate: certificate_base64,
    };

    let dapp_response = DAppResponse {
        id: Some(1),
        jsonrpc: "2.0".to_string(),
        result: Some(dapp_result),
        error: None,
    };

    // Store complete JSON response
    transaction.signature = serde_json::to_vec(&dapp_response)
        .map_err(|e| ChainError::InvalidData(format!("JSON encoding failed: {e}")))?;

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
        .map_err(|e| ChainError::InvalidData(format!("CBOR encoding failed: {e}")))?;

    Ok(cbor_bytes)
}

// Create a CallContentRequest from DApp parameters
fn create_call_request_from_dapp(params: ICRC49Params) -> Result<CallContentRequest, ChainError> {
    // Convert canister_id from string to bytes
    let canister_bytes = principal_to_bytes(&params.canister_id)?;

    // Convert sender from string to bytes
    let sender_bytes = principal_to_bytes(&params.sender)?;

    // Decode arguments from base64
    let arg_bytes = simple_base64_decode(&params.arg)
        .map_err(|e| ChainError::InvalidData(format!("Failed to decode arg: {e}")))?;

    // Calculate expiration time (4 minutes)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ChainError::InvalidData(format!("Time error: {e}")))?;

    let created_at = now.as_nanos() as i64;
    let expire_time: i64 = 240_000_000_000; // 4 minutes in nanoseconds
    let ingress_expiry = (created_at + expire_time) as u64;

    // Process optional nonce
    let nonce_bytes = if let Some(nonce_str) = params.nonce {
        Some(
            simple_base64_decode(&nonce_str)
                .map_err(|e| ChainError::InvalidData(format!("Failed to decode nonce: {e}")))?,
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

fn sort_byte_arrays(src: &mut [Vec<u8>]) {
    #[allow(clippy::unnecessary_sort_by)]
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

// Validate if an ICRC-49 request is valid
#[allow(dead_code)]
pub fn validate_icrc49_request(raw_data: &[u8]) -> Result<DAppRequest, ChainError> {
    let request: DAppRequest = serde_json::from_slice(raw_data)
        .map_err(|e| ChainError::InvalidTransaction(format!("Invalid JSON: {e}")))?;

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
    fn test_icrc49_request_hash() {
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

        let request = result.unwrap();

        let call_request = create_call_request_from_dapp(request.params).unwrap();

        let request_hash = calculate_call_request_hash(&call_request);

        assert!(request_hash.is_ok());

        let hash = request_hash.unwrap();

        assert_eq!(hash.len(), 43);
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
    fn test_regular_transaction_compatibility() {
        let raw_tx = hex::decode("35623232333036313336333933363333333236343337333233363335333733313337333533363335333733333337333433353332333133373635333533363336333433393636363633323331333233383333333636363330363133323332333633323336333736363333333036333631333033303635333836353334363633323635333833333334363236313336363333303634333236343338333233343332333733323336333933303337333033303232326332323330363133363339333633333332363433373332333633353337333133373335333633353337333333373334333136323331333433303632363236343337333633353337333136333330363133333334333333333331333333313338333533343333333736323635333836323338363236333334363433353635333233383339333833303331363136353631333133373635363133303336363136363332333036343331363533393337333532323564").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        assert!(matches!(
            detect_transaction_type(&tx.raw_data),
            TransactionType::Regular
        ));

        let mut result = encode_for_sign(tx.clone()).unwrap();

        assert_eq!(
            hex::encode(result.tx_hash.clone()),
            "020000002b0000000a69632d726571756573745217e56649ff212836f0a226267f30ca00e8e4f2e834ba6c0d2d8242726907002b0000000a69632d726571756573741b140bbd76571c0a343313185437be8b8bc4d5e289801aea17ea06af20d1e975"
        );

        result.signature = hex::decode("0200000040000000cfb3e72d741521a803a6a3769864413eef9500dfb5fb488d68b84066f8643785a69da83e2ec4c936e8408272ad96d1d461d4f91a26dd9fb43d21f9130a75b9064000000097ca0c2eef5673ee0528b3afa468cfd2bd3384b1dd98d3e4c9171855bed8b915c8b971ab8a842b5fb8fc78fdb7ca819753f355229d1fc0d57c3709e0615c0504").unwrap();

        let result = encode_for_broadcast(result.clone()).unwrap();

        assert_eq!(
            hex::encode(result.signature),
            "5b226366623365373264373431353231613830336136613337363938363434313365656639353030646662356662343838643638623834303636663836343337383561363964613833653265633463393336653834303832373261643936643164343631643466393161323664643966623433643231663931333061373562393036222c223937636130633265656635363733656530353238623361666134363863666432626433333834623164643938643365346339313731383535626564386239313563386239373161623861383432623566623866633738666462376361383139373533663335353232396431666330643537633337303965303631356330353034225d"
        );
    }
}
