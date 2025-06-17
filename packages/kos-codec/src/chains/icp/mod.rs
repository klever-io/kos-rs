use base32;
use base64;
use kos::chains::util::byte_vectors_to_bytes;
use kos::chains::{ChainError, Transaction};
use leb128;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_json_rs::serializer;

#[derive(Debug, Clone)]
enum TransactionType {
    Regular,
    DAppCall,
}

#[derive(Debug, Deserialize)]
pub struct DAppRequest {
    pub method: String,
    pub params: ICRC49Params,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ICRC49Params {
    pub canister_id: String,
    pub sender: String,
    pub method: String,
    pub arg: String, // Base64 encoded
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

fn detect_transaction_type(raw_data: &[u8]) -> TransactionType {
    if let Ok(dapp_request) = serde_json::from_slice::<DAppRequest>(raw_data.clone()) {
        if dapp_request.method == "icrc49_call_canister" {
            return TransactionType::DAppCall;
        }
    }

    TransactionType::Regular
}

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let transaction_type = detect_transaction_type(&transaction.raw_data);

    match transaction_type {
        TransactionType::Regular => {
            let hex =
                hex::decode(transaction.raw_data.clone()).map_err(|_| ChainError::DecodeRawTx)?;
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

            println!("{}", icp_hashes.len());

            for hash_hex in icp_hashes {
                hashes.push(hex::decode(hash_hex).unwrap());
            }

            transaction.tx_hash = byte_vectors_to_bytes(&hashes);
            Ok(transaction)
        }
        TransactionType::DAppCall => encode_dapp_for_sign(transaction),
    }
}

pub fn encode_dapp_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let dapp_request: DAppRequest = serde_json::from_slice(transaction.raw_data.as_slice())
        .map_err(|_| ChainError::InvalidTransaction("Failed to parse DApp request".to_string()))?;

    if dapp_request.method != "icrc49_call_canister" {
        return Err(ChainError::InvalidTransaction(dapp_request.method));
    }

    let call_request = create_call_request_from_dapp(dapp_request.params)?;

    let request_hash = calculate_call_request_hash(&call_request)?;

    transaction.tx_hash = request_hash;

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let transaction_type = detect_transaction_type(&transaction.raw_data);

    match transaction_type {
        TransactionType::Regular => {
            let signatures = bytes_to_byte_vectors(transaction.signature)?;

            let mut signatures_vec = Vec::new();
            for signature in signatures {
                signatures_vec.push(hex::encode(signature));
            }

            let signatures_json = tiny_json_rs::encode(signatures_vec);
            transaction.signature = signatures_json.into_bytes();
            Ok(transaction)
        }
        TransactionType::DAppCall => Ok(transaction),
    }
}

fn create_call_request_from_dapp(params: ICRC49Params) -> Result<CallContentRequest, ChainError> {
    let canister_bytes = principal_to_bytes(&params.canister_id)?;

    let sender_bytes = principal_to_bytes(&params.sender)?;

    // TODO: Use Engine::decode instead
    let arg_bytes =
        base64::decode(&params.arg).map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ChainError::InvalidData(e.to_string()))?;

    let created_at = now.as_nanos() as i64;
    let expire_time: i64 = 240_000_000_000;
    let ingress_expiry = (created_at + expire_time) as u64;

    Ok(CallContentRequest {
        request_type: "call".to_string(),
        canister_id: canister_bytes,
        method_name: params.method,
        arg: arg_bytes,
        sender: sender_bytes,
        ingress_expiry,
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

    calculate_payload_hash(request)
}

fn principal_to_bytes(principal_str: &str) -> Result<Vec<u8>, ChainError> {
    let str32 = principal_str.replace("-", "").to_uppercase();

    let envelope = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &str32)
        .ok_or_else(|| ChainError::InvalidData("Invalid base32 encoding".to_string()))?;

    if envelope.len() < 4 {
        return Err(ChainError::InvalidAccountLength);
    }

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

fn bytes_to_byte_vectors(bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, ChainError> {
    Ok(vec![bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dapp_transaction_encoding() {
        let dapp_request_json = r#"{
            "method": "icrc49_call_canister",
            "params": {
                "canisterId": "2wdkf-viaaa-aaaam-ackqq-cai",
                "sender": "sgyks-q7tq3-tczsp-tytog-mxwxi-qxnym-sfoh6-ky4rj-dxhls-ryvy7-zae",
                "method": "greet_no_consent",
                "arg": "RElETAABcQJtZQ=="
            }
        }"#;

        let mut transaction = Transaction {
            raw_data: dapp_request_json.to_string().as_bytes().to_vec(),
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        match encode_for_sign(transaction) {
            Ok(encoded_tx) => {
                println!("Hash for signing: {:?}", hex::encode(&encoded_tx.tx_hash));
                assert!(!encoded_tx.tx_hash.is_empty());
            }
            Err(e) => {
                panic!("Failed to encode DApp transaction: {:?}", e);
            }
        }
    }

    #[test]
    fn test_transaction_type_detection() {
        let dapp_request = r#"{
            "method": "icrc49_call_canister",
            "params": {
                "canisterId": "2wdkf-viaaa-aaaam-ackqq-cai",
                "sender": "sgyks-q7tq3-tczsp-tytog-mxwxi-qxnym-sfoh6-ky4rj-dxhls-ryvy7-zae",
                "method": "greet_no_consent",
                "arg": "RElETAABcQJtZQ=="
            }
        }"#
        .as_bytes();
        assert!(matches!(
            detect_transaction_type(dapp_request),
            TransactionType::DAppCall
        ));

        let regular_tx = "48656c6c6f20576f726c64".as_bytes();
        assert!(matches!(
            detect_transaction_type(regular_tx),
            TransactionType::Regular
        ));

        let other_json = r#"{"method": "other_method", "data": "test"}"#.as_bytes();
        assert!(matches!(
            detect_transaction_type(other_json),
            TransactionType::Regular
        ));
    }

    #[test]
    fn test_tx() {
        let raw_tx = hex::decode("35623232333036313336333933363333333236343337333233363335333733313337333533363335333733333337333433353332333133373635333533363336333433393636363633323331333233383333333636363330363133323332333633323336333736363333333036333631333033303635333836353334363633323635333833333334363236313336363333303634333236343338333233343332333733323336333933303337333033303232326332323330363133363339333633333332363433373332333633353337333133373335333633353337333333373334333136323331333433303632363236343337333633353337333136333330363133333334333333333331333333313338333533343333333736323635333836323338363236333334363433353635333233383339333833303331363136353631333133373635363133303336363136363332333036343331363533393337333532323564").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

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
