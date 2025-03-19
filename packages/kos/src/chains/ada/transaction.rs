use crate::chains::ChainError;
use crate::crypto::base64::simple_base64_decode;
use crate::crypto::hash::blake2b_digest;
use hex;
use minicbor::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode)]
pub struct Value {
    #[n(0)]
    pub coin: u64,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
pub struct TxInput {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub tx_hash: Vec<u8>,
    #[n(1)]
    pub index: u64,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
pub struct TxOutput {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub address: Vec<u8>,
    #[n(1)]
    pub amount: u64,
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum Certificate {}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Mint {}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(map)]
pub struct TxBody {
    #[n(0)]
    pub inputs: Vec<TxInput>,

    #[n(1)]
    pub outputs: Vec<TxOutput>,

    #[n(2)]
    pub fee: u64,

    #[n(3)]
    pub ttl: Option<u64>,
}
impl TxBody {
    pub fn hash(&self) -> Result<[u8; 32], ChainError> {
        let bytes = minicbor::to_vec(self).map_err(|e| ChainError::InvalidData(e.to_string()))?;

        let digest = blake2b_digest(bytes.as_slice());

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);

        Ok(hash)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ChainError> {
        minicbor::decode(bytes).map_err(|e| ChainError::InvalidData(e.to_string()))
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, ChainError> {
        minicbor::to_vec(self).map_err(|e| ChainError::InvalidData(e.to_string()))
    }
}

#[derive(Encode, Decode, Debug)]
#[cbor(array)]
pub struct VKeyWitness {
    #[n(0)]
    pub v_key: Vec<u8>,
    #[n(1)]
    pub signature: Vec<u8>,
}

#[derive(Encode, Decode, Debug)]
#[cbor(array)]
pub struct WitnessSet {
    #[n(0)]
    pub v_key_witness_set: Vec<VKeyWitness>,
}

#[derive(Encode, Decode, Debug)]
pub struct Tx {
    #[n(0)]
    pub body: Option<TxBody>,
    #[n(1)]
    pub witness_set: WitnessSet,
    #[n(2)]
    pub is_valid: bool,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub auxiliary_data: Option<Vec<u8>>,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaOperationIdentifier {
    #[n(0)]
    pub index: i32,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaAccount {
    #[n(0)]
    pub address: String,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaCoinIdentifier {
    #[n(0)]
    pub identifier: String,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaCoinChange {
    #[n(0)]
    pub coin_identifier: RosettaCoinIdentifier,
    #[n(1)]
    pub coin_action: String,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaBalance {
    #[n(0)]
    pub value: String,
    #[n(1)]
    pub currency: RosettaCurrency,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaCurrency {
    #[n(0)]
    pub symbol: String,
    #[n(1)]
    pub decimals: i32,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaOperation {
    #[n(0)]
    pub operation_identifier: RosettaOperationIdentifier,
    #[n(1)]
    pub r#type: String,
    #[n(2)]
    pub status: String,
    #[n(3)]
    pub account: RosettaAccount,
    #[n(4)]
    pub amount: RosettaBalance,
    #[n(5)]
    pub coin_change: RosettaCoinChange,
}

#[derive(Encode, Decode, Debug)]
#[cbor(map)]
pub struct RosettaTransactionOperations {
    #[n(0)]
    pub operations: Vec<RosettaOperation>,
}

#[derive(Encode, Decode, Debug)]
#[cbor(array)]
pub struct RosettaTransaction {
    #[n(0)]
    pub metadata: String,
    #[n(1)]
    pub operations: RosettaTransactionOperations,
}

#[test]
fn test_decode_tx() {
    let metadata = hex::decode("a40081825820d19c054099d89e22b5be557e24c02314de7ac93d7d1e602d3bbfc8684679d3c100018282583901af06fa5f1b28c90bdc1c87bbb6730bc0da986420c4bd00fd4e5dd1f2aeb0c747c68a403c2ece05a79881efe94aec2ec922fe4bd1c08e3d631a000f424082581d61d55f453f93954755913991d211952e4bddfccd9eea7e424967a779f41a010f71a1021a000336df031a08f71e95").unwrap();

    let tx_body: TxBody = minicbor::decode(&metadata).unwrap();

    println!("Decoded: {:?}", tx_body);
}
#[test]
fn test_decode_tx2() {
    let metadata = simple_base64_decode("gnkBNmE0MDA4MTgyNTgyMDMyMjJkOGFhNmQ1NDUzMzZmNTg3YTMyMjMxMTMwMWQ5OTRkMmE4NmY0Y2Q0YWQ2NjM5Nzc4MjQ1ZjgzY2Q5NWQwMDAxODI4MjU4MzkwMWFmMDZmYTVmMWIyOGM5MGJkYzFjODdiYmI2NzMwYmMwZGE5ODY0MjBjNGJkMDBmZDRlNWRkMWYyYWViMGM3NDdjNjhhNDAzYzJlY2UwNWE3OTg4MWVmZTk0YWVjMmVjOTIyZmU0YmQxYzA4ZTNkNjMxYTAwMGY0MjQwODI1ODFkNjFkODYyN2NmYzM5ZTVkMmY2ZjMxMDczMTRkNjNhYTNiZTc5YTg4MmFlZjE3OTdhMzlkMzMzMjNjZTFhMDkyNTkzNDMwMjFhMDAwMzM2ZGYwMzFhMDhmZGE3ODiham9wZXJhdGlvbnOBpnRvcGVyYXRpb25faWRlbnRpZmllcqFlaW5kZXgAZHR5cGVlaW5wdXRmc3RhdHVzYGdhY2NvdW50oWdhZGRyZXNzeDphZGRyMXY4dnh5bDh1ODhqYTlhaG56cGUzZjQzNjV3bDhuMnl6NG1jaGo3M2U2dmVqOG5zZ3RoaHVsZmFtb3VudKJldmFsdWVpMTU0NjY4MTMwaGN1cnJlbmN5omZzeW1ib2xjQURBaGRlY2ltYWxzBmtjb2luX2NoYW5nZaJvY29pbl9pZGVudGlmaWVyoWppZGVudGlmaWVyeEIzMjIyZDhhYTZkNTQ1MzM2ZjU4N2EzMjIzMTEzMDFkOTk0ZDJhODZmNGNkNGFkNjYzOTc3ODI0NWY4M2NkOTVkOjBrY29pbl9hY3Rpb25qY29pbl9zcGVudA==").unwrap();

    let tx_body: RosettaTransaction = minicbor::decode(&metadata).unwrap();

    println!("Decoded: {:?}", tx_body);
}
