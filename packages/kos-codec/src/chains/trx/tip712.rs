use hex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[allow(dead_code)]
#[derive(Debug)]
pub enum StructuredDataError {
    InvalidType(String),
    TypeNotFound(String),
    InvalidData(String),
    ParseError(String),
    Other(String),
}

impl fmt::Display for StructuredDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StructuredDataError::InvalidType(msg) => write!(f, "Invalid type: {}", msg),
            StructuredDataError::TypeNotFound(msg) => write!(f, "Type not found: {}", msg),
            StructuredDataError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            StructuredDataError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            StructuredDataError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl Error for StructuredDataError {}

type Result<T> = std::result::Result<T, StructuredDataError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredData {
    pub types: HashMap<String, Vec<Entry>>,
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

// Structure to store information about a parsed type
#[derive(Debug, Clone)]
pub struct ParsedType {
    pub base_type: String,
    pub is_array: bool,
    pub array_length: Option<usize>,
    pub is_reference: bool,
}

// Independent utility functions

// Function to calculate the Keccak256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);

    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());

    result
}

// Parse a Solidity data type
fn parse_type(type_str: &str, types_set: &HashSet<String>) -> Result<ParsedType> {
    // Regular expression to identify arrays
    let re_array = Regex::new(r"^([a-zA-Z0-9_]+)(\[([0-9]*)\])?$").unwrap();

    if let Some(caps) = re_array.captures(type_str) {
        let base_type = caps.get(1).unwrap().as_str();
        let is_array = caps.get(2).is_some();
        let array_length = if let Some(length_str) = caps.get(3) {
            if length_str.as_str().is_empty() {
                None // Dynamic array []
            } else {
                // Fixed-size array [N]
                Some(length_str.as_str().parse::<usize>().map_err(|e| {
                    StructuredDataError::ParseError(format!("Invalid array length: {}", e))
                })?)
            }
        } else {
            None // Not an array
        };

        // Check if the base type is a reference type (custom type)
        let is_reference = types_set.contains(base_type);

        let parsed = ParsedType {
            base_type: base_type.to_string(),
            is_array,
            array_length,
            is_reference,
        };

        return Ok(parsed);
    }

    // Basic type or reference type, not an array
    let is_reference = types_set.contains(type_str);

    let parsed = ParsedType {
        base_type: type_str.to_string(),
        is_array: false,
        array_length: None,
        is_reference,
    };

    Ok(parsed)
}

// Find recursive dependencies of a type
fn find_type_dependencies(
    primary_type: &str,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
    deps: &mut HashSet<String>,
) -> Result<()> {
    if !types_set.contains(primary_type) {
        return Err(StructuredDataError::TypeNotFound(primary_type.to_string()));
    }

    deps.insert(primary_type.to_string());

    if let Some(fields) = types.get(primary_type) {
        for field in fields {
            let parsed_type = parse_type(&field.r#type, types_set)?;

            // If it's a reference type, add to dependencies
            if parsed_type.is_reference {
                find_type_dependencies(&parsed_type.base_type, types, types_set, deps)?;
            }

            // If it's an array of reference types, add the array's base type
            if parsed_type.is_array && types_set.contains(&parsed_type.base_type) {
                find_type_dependencies(&parsed_type.base_type, types, types_set, deps)?;
            }
        }
    }

    Ok(())
}

// Encode a single type with its fields
fn encode_single_type(type_name: &str, types: &HashMap<String, Vec<Entry>>) -> Result<String> {
    if !types.contains_key(type_name) {
        return Err(StructuredDataError::TypeNotFound(type_name.to_string()));
    }

    let fields = &types[type_name];

    let mut result = String::new();
    result.push_str(type_name);
    result.push('(');

    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(&field.r#type);
        result.push(' ');
        result.push_str(&field.name);
    }

    result.push(')');
    Ok(result)
}

// Encode a complex type with all its dependencies
fn encode_type(
    primary_type: &str,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<String> {
    let mut deps = HashSet::new();
    find_type_dependencies(primary_type, types, types_set, &mut deps)?;

    // Remove primary_type from dependencies
    deps.remove(primary_type);

    // Sort the dependencies
    let mut sorted_deps: Vec<String> = deps.into_iter().collect();
    sorted_deps.sort();

    // Add the primary type at the beginning
    let mut result = encode_single_type(primary_type, types)?;

    // For each dependency, add its representation
    for dep in sorted_deps {
        result.push_str(&encode_single_type(&dep, types)?);
    }

    Ok(result)
}

// Calculate the hash of a type
fn type_hash(
    primary_type: &str,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<[u8; 32]> {
    let encoded_type = encode_type(primary_type, types, types_set)?;
    Ok(keccak256(encoded_type.as_bytes()))
}

// Functions for encoding specific types

// Encode a string
fn encode_string(value: &Value) -> Result<Vec<u8>> {
    let value_str = value
        .as_str()
        .ok_or_else(|| StructuredDataError::InvalidData("Expected string value".to_string()))?;

    Ok(keccak256(value_str.as_bytes()).to_vec())
}

// Encode bytes
fn encode_bytes(value: &Value) -> Result<Vec<u8>> {
    let value_str = value
        .as_str()
        .ok_or_else(|| StructuredDataError::InvalidData("Expected bytes as string".to_string()))?;

    // Remove the 0x prefix if it exists
    let bytes_str = value_str.strip_prefix("0x").unwrap_or(value_str);

    // Convert from hex to bytes
    let bytes = hex::decode(bytes_str)
        .map_err(|_| StructuredDataError::InvalidData("Invalid hex string".to_string()))?;

    Ok(keccak256(&bytes).to_vec())
}

// Encode numeric values
fn encode_integer(value: &Value) -> Result<Vec<u8>> {
    // Convert to numeric values
    let value_num = if value.is_number() {
        value
            .as_u64()
            .or_else(|| value.as_i64().map(|v| v as u64))
            .ok_or_else(|| StructuredDataError::InvalidData("Expected numeric value".to_string()))?
    } else if value.is_string() {
        let value_str = value.as_str().unwrap();
        let parse_result = if let Some(hex_body) = value_str.strip_prefix("0x") {
            u64::from_str_radix(hex_body, 16)
        } else {
            value_str.parse::<u64>()
        };

        parse_result
            .map_err(|_| StructuredDataError::InvalidData("Invalid numeric value".to_string()))?
    } else {
        return Err(StructuredDataError::InvalidData(
            "Expected numeric value".to_string(),
        ));
    };

    // Encode as uint256/int256 (32 bytes)
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[31 - i] = ((value_num >> (i * 8)) & 0xFF) as u8;
    }

    Ok(result.to_vec())
}

// Encode a boolean value
fn encode_bool(value: &Value) -> Result<Vec<u8>> {
    let value_bool = value
        .as_bool()
        .ok_or_else(|| StructuredDataError::InvalidData("Expected boolean value".to_string()))?;

    let mut result = [0u8; 32];
    result[31] = if value_bool { 1 } else { 0 };

    Ok(result.to_vec())
}

// Decode a Tron address from base58 encoding
fn bs58_decode(input: &str) -> Result<Vec<u8>> {
    // This function should use a real library like bs58
    // Here is an example implementation using the bs58 library
    bs58::decode(input).into_vec().map_err(|e| {
        StructuredDataError::InvalidData(format!("Failed to decode base58 string: {}", e))
    })
}

// Encode an address
fn encode_address(value: &Value) -> Result<Vec<u8>> {
    let value_str = value.as_str().ok_or_else(|| {
        StructuredDataError::InvalidData("Expected address as string".to_string())
    })?;

    // For Tron addresses, remove the 0x41 prefix if present
    // and convert from base58 to bytes
    let address_bytes = if value_str.starts_with("T") {
        // Tron address conversion (base58) to bytes
        let decoded = bs58_decode(value_str)?;

        // Remove the 0x41 prefix
        if decoded.len() > 1 && decoded[0] == 0x41 {
            decoded[1..].to_vec()
        } else {
            decoded
        }
    } else if let Some(hex_body) = value_str.strip_prefix("0x") {
        hex::decode(hex_body)
            .map_err(|_| StructuredDataError::InvalidData("Invalid hex address".to_string()))?
    } else {
        // Try to decode as a Tron address without the 'T' prefix
        let decoded = bs58_decode(value_str)?;

        // Remove the 0x41 prefix if present
        if decoded.len() > 1 && decoded[0] == 0x41 {
            decoded[1..].to_vec()
        } else {
            decoded
        }
    };

    // Pad with leading zeros to 32 bytes
    let mut result = [0u8; 32];
    let start_idx = 32 - std::cmp::min(address_bytes.len(), 20); // Addresses should not be longer than 20 bytes

    for (i, b) in address_bytes.iter().take(20).enumerate() {
        result[start_idx + i] = *b;
    }

    Ok(result.to_vec())
}

// Encode an array
fn encode_array(
    element_type: &str,
    array_length: Option<usize>,
    values: &[Value],
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<Vec<u8>> {
    // For fixed arrays, check if the length matches
    if let Some(expected_length) = array_length {
        if values.len() != expected_length {
            return Err(StructuredDataError::InvalidData(format!(
                "Expected array of length {}, got {}",
                expected_length,
                values.len()
            )));
        }
    }

    // Dynamic arrays are encoded with the hash of the concatenation of their elements
    if array_length.is_none() {
        let mut encoded_items = Vec::new();

        for item in values {
            let encoded_item = encode_field(element_type, item, types, types_set)?;
            encoded_items.extend_from_slice(&encoded_item);
        }

        return Ok(keccak256(&encoded_items).to_vec());
    }

    // Fixed arrays are encoded as the concatenation of their elements
    let mut encoded = Vec::new();

    for item in values {
        let encoded_item = encode_field(element_type, item, types, types_set)?;
        encoded.extend_from_slice(&encoded_item);
    }

    Ok(encoded)
}

// Encode a specific field
fn encode_field(
    field_type: &str,
    value: &Value,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<Vec<u8>> {
    let parsed_type = parse_type(field_type, types_set)?;

    // Handle arrays
    if parsed_type.is_array {
        if !value.is_array() {
            return Err(StructuredDataError::InvalidData(format!(
                "Expected array value for type {}",
                parsed_type.base_type
            )));
        }

        return encode_array(
            &parsed_type.base_type,
            parsed_type.array_length,
            value.as_array().unwrap(),
            types,
            types_set,
        );
    }

    // Handle trcToken type as uint256
    if parsed_type.base_type == "trcToken" {
        return encode_integer(value);
    }

    // Check if it is a known type (struct)
    if parsed_type.is_reference {
        // It is a struct type
        return hash_struct(&parsed_type.base_type, value, types, types_set);
    }

    // Basic types
    match parsed_type.base_type.as_str() {
        "string" => encode_string(value),
        "bytes" => encode_bytes(value),
        t if t.starts_with("uint") || t.starts_with("int") => encode_integer(value),
        "bool" => encode_bool(value),
        "address" => encode_address(value),
        // Add other types as needed
        _ => Err(StructuredDataError::InvalidType(format!(
            "Unsupported type: {}",
            field_type
        ))),
    }
}

// Encode all data for a struct
fn encode_data(
    type_name: &str,
    data: &Value,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<Vec<u8>> {
    if !types.contains_key(type_name) {
        return Err(StructuredDataError::TypeNotFound(type_name.to_string()));
    }

    let fields = &types[type_name];
    let mut encoded = Vec::new();

    for field in fields {
        let field_name = &field.name;
        let field_type = &field.r#type;

        // Get the field value from the data
        let value = match data.get(field_name) {
            Some(v) => v,
            None => {
                return Err(StructuredDataError::InvalidData(format!(
                    "Field {} not found in data",
                    field_name
                )))
            }
        };

        let encoded_value = encode_field(field_type, value, types, types_set)?;
        encoded.extend_from_slice(&encoded_value);
    }

    Ok(encoded)
}

// Calculate the hash of a struct
fn hash_struct(
    type_name: &str,
    data: &Value,
    types: &HashMap<String, Vec<Entry>>,
    types_set: &HashSet<String>,
) -> Result<Vec<u8>> {
    if !types.contains_key(type_name) {
        return Err(StructuredDataError::TypeNotFound(type_name.to_string()));
    }

    let type_hash_value = type_hash(type_name, types, types_set)?;
    let encoded_data = encode_data(type_name, data, types, types_set)?;

    // Concatenate type_hash + encoded_data
    let mut buffer = Vec::with_capacity(type_hash_value.len() + encoded_data.len());
    buffer.extend_from_slice(&type_hash_value);
    buffer.extend_from_slice(&encoded_data);

    Ok(keccak256(&buffer).to_vec())
}

// Calculate the domain hash
fn hash_domain(data: &StructuredData, types_set: &HashSet<String>) -> Result<[u8; 32]> {
    // For TIP-712, the domain is encoded as "TIP712Domain"
    // Check if it explicitly exists in types
    let domain_type = if data.types.contains_key("TIP712Domain") {
        "TIP712Domain"
    } else if data.types.contains_key("EIP712Domain") {
        // Fallback for Ethereum compatibility
        "EIP712Domain"
    } else {
        return Err(StructuredDataError::TypeNotFound(
            "Neither TIP712Domain nor EIP712Domain found in types".to_string(),
        ));
    };

    let hash = hash_struct(domain_type, &data.domain, &data.types, types_set)?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);

    Ok(result)
}

// Calculate the final hash of a structured document
fn hash_typed_data(data: &StructuredData) -> Result<[u8; 32]> {
    // Create the set of types
    let mut types_set = HashSet::new();
    for (type_name, _) in data.types.iter() {
        types_set.insert(type_name.to_string());
    }

    let domain_hash = hash_domain(data, &types_set)?;

    let primary_hash = hash_struct(&data.primary_type, &data.message, &data.types, &types_set)?;

    // Concatenate according to TIP-712 specification
    let mut buffer = Vec::with_capacity(2 + domain_hash.len() + primary_hash.len());
    buffer.extend_from_slice(&[0x19, 0x01]);
    buffer.extend_from_slice(&domain_hash);
    buffer.extend_from_slice(&primary_hash);

    Ok(keccak256(&buffer))
}

// High-level function for JSON to hash conversion
pub fn hash_typed_data_json(json_data: &str) -> Result<[u8; 32]> {
    let mut typed_data: StructuredData = serde_json::from_str(json_data)
        .map_err(|e| StructuredDataError::InvalidData(format!("Invalid JSON: {}", e)))?;

    let eip712_domain_entries = vec![
        Entry {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        Entry {
            name: String::from("version"),
            r#type: String::from("string"),
        },
        Entry {
            name: String::from("chainId"),
            r#type: String::from("uint256"),
        },
        Entry {
            name: String::from("verifyingContract"),
            r#type: String::from("address"),
        },
    ];

    // Insert the vector into the HashMap with the key "EIP712Domain"
    typed_data
        .types
        .insert(String::from("EIP712Domain"), eip712_domain_entries);

    let hash = hash_typed_data(&typed_data)?;

    Ok(hash)
}

#[cfg(test)]
#[test]
fn test_hash_struct() {
    let data = r#"{
    "types": {
    "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
        "PermitTransfer": [
            {
                "name": "token",
                "type": "address"
            },
            {
                "name": "serviceProvider",
                "type": "address"
            },
            {
                "name": "user",
                "type": "address"
            },
            {
                "name": "receiver",
                "type": "address"
            },
            {
                "name": "value",
                "type": "uint256"
            },
            {
                "name": "maxFee",
                "type": "uint256"
            },
            {
                "name": "deadline",
                "type": "uint256"
            },
            {
                "name": "version",
                "type": "uint256"
            },
            {
                "name": "nonce",
                "type": "uint256"
            }
        ]
    },
    "primaryType": "PermitTransfer",
    "domain": {
        "name": "GasFreeController",
        "version": "V1.0.0",
        "chainId": 728126428,
        "verifyingContract": "TFFAMQLZybALaLb4uxHA9RBE7pxhUAjF3U"
    },
    "message": {
        "token": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "serviceProvider": "TLntW9Z59LYY5KEi9cmwk3PKjQga828ird",
        "user": "TCXs584P995owJmBifUZqNUUD6BSnBmvot",
        "receiver": "TGJSxpAWwaUoqT8sLFxX2TD7BP7MrpdwWo",
        "value": "1000000",
        "maxFee": "2000000",
        "deadline": "1746015449",
        "version": "1",
        "nonce": "1"
    }
}"#;

    let typed_data: StructuredData = serde_json::from_str(data).unwrap();

    let digest = hash_typed_data(&typed_data).unwrap();
    assert_eq!(
        hex::encode(digest),
        "a546b17147e14ec2aa418ca2eb7490bacaa60453cf902e292b01f02e02e83264"
    );
}
