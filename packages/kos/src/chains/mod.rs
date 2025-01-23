use crate::alloc::borrow::ToOwned;
use crate::crypto::bip32::Bip32Err;
use crate::crypto::ed25519::Ed25519Err;
use crate::crypto::secp256k1::Secp256Err;
use crate::crypto::sr25519::Sr25519Error;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{FromUtf8Error, String, ToString};
use alloc::vec::Vec;
use core::fmt::Display;
use prost::{DecodeError, EncodeError};
use rlp::DecoderError;
use tiny_json_rs::lexer::StringType;
use tiny_json_rs::mapper;
use tiny_json_rs::serializer;
use tiny_json_rs::serializer::Token;
use tiny_json_rs::Serialize;

pub mod ada;
mod apt;
mod atom;
mod bch;
mod bnb;
mod btc;
pub mod constants;
pub mod egld;
mod eth;
mod icp;
pub mod klv;
mod sol;
mod substrate;
mod sui;
pub mod trx;
mod util;
mod xrp;

#[derive(Debug)]
pub enum ChainError {
    ErrDerive,
    InvalidPrivateKey,
    ProtoDecodeError,
    CurveError(Secp256Err),
    CurveErrorSr(Sr25519Error),
    EncodeError(EncodeError),
    DecodeError(DecodeError),
    Ed25519Error,
    Bech32EncodeError,
    RlpError,
    InvalidMessageSize,
    InvalidSignature,
    NotSupported,
    InvalidPublicKey,
    InvalidSeed,
    InvalidCredential,
    InvalidMnemonic,
    CipherError(String),
    InvalidString(String),
    InvalidData(String),
    MissingOptions,
    InvalidOptions,
}

impl Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::ErrDerive => write!(f, "Derive error"),
            ChainError::InvalidPrivateKey => write!(f, "Invalid private key"),
            ChainError::CurveError(e) => write!(f, "Curve error: {}", e),
            ChainError::ProtoDecodeError => {
                write!(f, "Proto decode error")
            }
            ChainError::EncodeError(e) => {
                write!(f, "encode error: {}", e)
            }
            ChainError::DecodeError(e) => {
                write!(f, "decode error: {}", e)
            }
            ChainError::Ed25519Error => {
                write!(f, "ed25519 error")
            }
            ChainError::Bech32EncodeError => {
                write!(f, "bech32 encode error")
            }
            ChainError::RlpError => {
                write!(f, "rlp error")
            }
            ChainError::InvalidMessageSize => {
                write!(f, "invalid message size")
            }
            ChainError::InvalidSignature => {
                write!(f, "invalid signature")
            }
            ChainError::NotSupported => {
                write!(f, "not supported")
            }
            ChainError::InvalidPublicKey => {
                write!(f, "invalid public key")
            }
            ChainError::CurveErrorSr(e) => {
                write!(f, "curve error sr: {}", e)
            }
            ChainError::InvalidSeed => {
                write!(f, "invalid seed")
            }
            ChainError::InvalidCredential => {
                write!(f, "invalid credential")
            }
            ChainError::InvalidMnemonic => {
                write!(f, "invalid mnemonic")
            }
            ChainError::CipherError(e) => {
                write!(f, "cipher error: {}", e)
            }
            ChainError::InvalidString(e) => {
                write!(f, "invalid string: {}", e)
            }
            ChainError::InvalidData(e) => {
                write!(f, "invalid data: {}", e)
            }
            ChainError::MissingOptions => {
                write!(f, "missing option")
            }
            ChainError::InvalidOptions => {
                write!(f, "invalid option")
            }
        }
    }
}

impl From<Secp256Err> for ChainError {
    fn from(value: Secp256Err) -> Self {
        ChainError::CurveError(value)
    }
}

impl From<Ed25519Err> for ChainError {
    fn from(_: Ed25519Err) -> Self {
        ChainError::Ed25519Error
    }
}

impl From<Bip32Err> for ChainError {
    fn from(_: Bip32Err) -> Self {
        ChainError::ErrDerive
    }
}

impl From<FromUtf8Error> for ChainError {
    fn from(_: FromUtf8Error) -> Self {
        ChainError::InvalidPrivateKey
    }
}

impl From<DecodeError> for ChainError {
    fn from(v: DecodeError) -> Self {
        ChainError::DecodeError(v)
    }
}

impl From<EncodeError> for ChainError {
    fn from(v: EncodeError) -> Self {
        ChainError::EncodeError(v)
    }
}

impl From<bech32::Error> for ChainError {
    fn from(_: bech32::Error) -> Self {
        ChainError::Bech32EncodeError
    }
}

impl From<DecoderError> for ChainError {
    fn from(_: DecoderError) -> Self {
        ChainError::RlpError
    }
}

impl From<serializer::DecodeError> for ChainError {
    fn from(_: serializer::DecodeError) -> Self {
        ChainError::ProtoDecodeError
    }
}

impl From<Sr25519Error> for ChainError {
    fn from(value: Sr25519Error) -> Self {
        ChainError::CurveErrorSr(value)
    }
}

#[allow(dead_code)]
impl ChainError {
    pub fn to_u32(&self) -> u32 {
        match self {
            ChainError::ErrDerive => 1,
            ChainError::InvalidPrivateKey => 2,
            ChainError::ProtoDecodeError => 3,
            ChainError::CurveError(_) => 4,
            ChainError::EncodeError(_) => 5,
            ChainError::DecodeError(_) => 6,
            ChainError::Ed25519Error => 7,
            ChainError::Bech32EncodeError => 8,
            ChainError::RlpError => 9,
            ChainError::InvalidMessageSize => 10,
            ChainError::InvalidSignature => 11,
            ChainError::NotSupported => 12,
            ChainError::InvalidPublicKey => 13,
            ChainError::CurveErrorSr(_) => 14,
            ChainError::InvalidSeed => 15,
            ChainError::InvalidCredential => 16,
            ChainError::InvalidMnemonic => 17,
            ChainError::CipherError(_) => 18,
            ChainError::InvalidString(_) => 19,
            ChainError::InvalidData(_) => 20,
            ChainError::MissingOptions => 21,
            ChainError::InvalidOptions => 22,
        }
    }
}

pub enum TxType {
    Unknown,
    Transfer,
    TriggerContract,
}

impl serializer::Serialize for TxType {
    fn serialize(&self) -> mapper::Value {
        let str = match self {
            TxType::Unknown => "Unknown",
            TxType::Transfer => "Transfer",
            TxType::TriggerContract => "TriggerContract",
        };
        let token = Token {
            token_type: tiny_json_rs::lexer::TokenType::String(StringType::SimpleString),
            literal: str.to_string(),
        };

        mapper::Value::Token(token)
    }
}

#[derive(Serialize)]
pub struct TxInfo {
    pub sender: String,
    pub receiver: String,
    pub value: f64,
    pub tx_type: TxType,
}

pub struct Transaction {
    pub raw_data: Vec<u8>,
    pub tx_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub options: Option<ChainOptions>,
}

#[derive(Clone)]
pub enum ChainOptions {
    EVM {
        chain_id: u32,
    },
    BTC {
        prev_scripts: Vec<Vec<u8>>,
        input_amounts: Vec<u64>,
    },
}

#[allow(dead_code)]
impl Transaction {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            raw_data: Vec::new(),
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        }
    }
}

pub trait Chain {
    fn get_id(&self) -> u32;
    fn get_name(&self) -> &str;
    fn get_symbol(&self) -> &str;
    fn get_decimals(&self) -> u32;
    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError>;
    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError>;
    fn get_path(&self, index: u32, is_legacy: bool) -> String;
    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError>;
    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError>;
    fn sign_tx(&self, private_key: Vec<u8>, tx: Transaction) -> Result<Transaction, ChainError>;
    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError>;
    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError>;
    fn get_tx_info(&self, raw_tx: Vec<u8>) -> Result<TxInfo, ChainError>;
}

type ChainFactory = fn() -> Box<dyn Chain>;

struct ChainInfo {
    factory: ChainFactory,
    supported: bool,
}

struct ChainRegistry {
    registry: &'static [(u32, ChainInfo)],
}
impl ChainRegistry {
    fn new() -> Self {
        static REGISTRY: [(u32, ChainInfo); 46] = [
            (
                constants::ETH,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new()),
                    supported: true,
                },
            ),
            (
                constants::BSC,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(26, 56, "BSC", "BnbSmartChain")),
                    supported: true,
                },
            ),
            (
                constants::POLYGON,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(28, 137, "MATIC", "Polygon")),
                    supported: true,
                },
            ),
            (
                constants::HT,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(30, 128, "HT", "Huobi")),
                    supported: true,
                },
            ),
            (
                constants::SYS_NEVM,
                ChainInfo {
                    factory: || {
                        Box::new(eth::ETH::new_eth_based(37, 57, "SYS_NEVM", "Syscoin Nevm"))
                    },
                    supported: true,
                },
            ),
            (
                constants::TRX,
                ChainInfo {
                    factory: || Box::new(trx::TRX {}),
                    supported: true,
                },
            ),
            (
                constants::KLV,
                ChainInfo {
                    factory: || Box::new(klv::KLV {}),
                    supported: true,
                },
            ),
            (
                constants::BTC,
                ChainInfo {
                    factory: || Box::new(btc::BTC::new()),
                    supported: true,
                },
            ),
            (
                constants::DOT,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(21, 0, "DOT", "Polkadot")),
                    supported: true,
                },
            ),
            (
                constants::KSM,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(27, 2, "KSM", "Kusama")),
                    supported: true,
                },
            ),
            (
                constants::LTC,
                ChainInfo {
                    factory: || Box::new(btc::BTC::new_btc_based(5, "ltc", "LTC", "Litecoin")),
                    supported: false,
                },
            ),
            (
                constants::REEF,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(29, 42, "REEF", "Reef")),
                    supported: true,
                },
            ),
            (
                constants::SDN,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(35, 5, "SDN", "Shiden")),
                    supported: true,
                },
            ),
            (
                constants::ASTR,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(36, 5, "ASTR", "Astar")),
                    supported: true,
                },
            ),
            (
                constants::CFG,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(47, 36, "CFG", "Centrifuge")),
                    supported: true,
                },
            ),
            (
                constants::SYS,
                ChainInfo {
                    factory: || Box::new(btc::BTC::new_btc_based(15, "sys", "SYS", "Syscoin")),
                    supported: false,
                },
            ),
            (
                constants::KILT,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(44, 38, "KILT", "KILT")),
                    supported: true,
                },
            ),
            (
                constants::ALTAIR,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(42, 136, "ALTAIR", "Altair")),
                    supported: true,
                },
            ),
            (
                constants::DOGE,
                ChainInfo {
                    factory: || {
                        Box::new(btc::BTC::new_legacy_btc_based(12, 0x1E, "DOGE", "Dogecoin"))
                    },
                    supported: false,
                },
            ),
            (
                constants::DASH,
                ChainInfo {
                    factory: || Box::new(btc::BTC::new_legacy_btc_based(11, 0x4C, "DASH", "Dash")),
                    supported: false,
                },
            ),
            (
                constants::XRP,
                ChainInfo {
                    factory: || Box::new(xrp::XRP::new()),
                    supported: false,
                },
            ),
            (
                constants::DGB,
                ChainInfo {
                    factory: || Box::new(btc::BTC::new_btc_based(16, "dgb", "DGB", "Digibyte")),
                    supported: false,
                },
            ),
            (
                constants::COSMOS,
                ChainInfo {
                    factory: || Box::new(atom::ATOM::new()),
                    supported: false,
                },
            ),
            (
                constants::CELESTIA,
                ChainInfo {
                    factory: || {
                        Box::new(atom::ATOM::new_cosmos_based(
                            "celestia", "celestia", "Celestia", "TIA",
                        ))
                    },
                    supported: false,
                },
            ),
            (
                constants::CUDOS,
                ChainInfo {
                    factory: || {
                        Box::new(atom::ATOM::new_cosmos_based(
                            "cudos", "cudos-1", "Cudos", "CUDOS",
                        ))
                    },
                    supported: false,
                },
            ),
            (
                constants::AURA,
                ChainInfo {
                    factory: || {
                        Box::new(atom::ATOM::new_cosmos_based(
                            "aura", "xstaxy-1", "Aura", "AURA",
                        ))
                    },
                    supported: false,
                },
            ),
            (
                constants::ICP,
                ChainInfo {
                    factory: || Box::new(icp::ICP {}),
                    supported: false,
                },
            ),
            (
                constants::SOL,
                ChainInfo {
                    factory: || Box::new(sol::SOL {}),
                    supported: false,
                },
            ),
            (
                constants::MOVR,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(32, 1285, "MOVR", "Moonriver")),
                    supported: true,
                },
            ),
            (
                constants::GLMR,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(34, 1284, "GLMR", "Moonbeam")),
                    supported: true,
                },
            ),
            (
                constants::BNB,
                ChainInfo {
                    factory: || Box::new(bnb::BNB {}),
                    supported: false,
                },
            ),
            (
                constants::BCH,
                ChainInfo {
                    factory: || Box::new(bch::BCH {}),
                    supported: false,
                },
            ),
            (
                constants::ADA,
                ChainInfo {
                    factory: || Box::new(ada::ADA {}),
                    supported: false,
                },
            ),
            (
                constants::SUI,
                ChainInfo {
                    factory: || Box::new(sui::SUI {}),
                    supported: true,
                },
            ),
            (
                constants::APT,
                ChainInfo {
                    factory: || Box::new(apt::APT {}),
                    supported: false,
                },
            ),
            (
                constants::AVAIL,
                ChainInfo {
                    factory: || Box::new(substrate::Substrate::new(62, 42, "AVAIL", "Avail")),
                    supported: true,
                },
            ),
            (
                constants::ROLLUX,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(63, 570, "ROLLUX", "Rollux")),
                    supported: true,
                },
            ),
            (
                constants::AVAX,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(39, 43114, "AVAX", "Avalanche")),
                    supported: true,
                },
            ),
            (
                constants::ARB,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(57, 42161, "ARB", "Arbitrum")),
                    supported: true,
                },
            ),
            (
                constants::BASE,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(60, 8453, "BASE", "Base")),
                    supported: true,
                },
            ),
            (
                constants::NEAR,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(64, 397, "NEAR", "Near")),
                    supported: true,
                },
            ),
            (
                constants::FTM,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(54, 250, "FTM", "Fantom")),
                    supported: true,
                },
            ),
            (
                constants::CHZ,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(61, 88888, "CHZ", "Chiliz")),
                    supported: true,
                },
            ),
            (
                constants::OP,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(53, 10, "OP", "Optimism")),
                    supported: true,
                },
            ),
            (
                constants::POLYGON_ZKEVM,
                ChainInfo {
                    factory: || {
                        Box::new(eth::ETH::new_eth_based(52, 1101, "ZKEVM", "Polygon zkEVM"))
                    },
                    supported: true,
                },
            ),
            (
                constants::STOLZ,
                ChainInfo {
                    factory: || Box::new(eth::ETH::new_eth_based(67, 2344, "STOLZ", "Stolz")),
                    supported: true,
                },
            ),
        ];

        Self {
            registry: &REGISTRY,
        }
    }

    fn get_chain_by_id(&self, id: u32) -> Option<Box<dyn Chain>> {
        for &(chain_id, ref chain_info) in self.registry {
            if chain_id == id {
                return Some((chain_info.factory)());
            }
        }
        None
    }

    fn get_chain_by_base_id(&self, base_id: u32) -> Option<Box<dyn Chain>> {
        for (_, chain_info) in self.registry {
            let chain = (chain_info.factory)();
            if chain.get_id() == base_id {
                return Some(chain);
            }
        }
        None
    }

    fn get_chains(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for (_, chain_info) in self.registry {
            let chain = (chain_info.factory)();
            ids.push(chain.get_id());
        }
        ids
    }

    fn is_chain_supported(&self, id: u32) -> bool {
        for (_, chain_info) in self.registry {
            let chain = (chain_info.factory)();
            if chain.get_id() == id {
                return chain_info.supported;
            }
        }
        false
    }

    fn get_supported_chains(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for (_, chain_info) in self.registry {
            let chain = (chain_info.factory)();
            if chain_info.supported {
                ids.push(chain.get_id());
            }
        }
        ids
    }

    fn create_custom_evm(&self, chain_id: u32) -> Option<Box<dyn Chain>> {
        Some(Box::new(eth::ETH::new_eth_based(
            0,
            chain_id,
            format!("ETH {}", chain_id).as_str(),
            format!("Eth Based {}", chain_id).as_str(),
        )))
    }
}

pub fn get_chain_by_id(id: u32) -> Option<Box<dyn Chain>> {
    ChainRegistry::new().get_chain_by_id(id)
}

pub enum CustomChainType {
    NotCustom(u32),
    CustomEth(u32),
    CustomSubstrate(u32),
    CustomCosmos(String),
}

pub fn get_chain_by_params(params: CustomChainType) -> Option<Box<dyn Chain>> {
    match params {
        CustomChainType::NotCustom(c) => get_chain_by_id(c),
        CustomChainType::CustomEth(chaincode) => Some(Box::new(eth::ETH::new_eth_based(
            0,
            chaincode,
            format!("ETH {}", chaincode).as_str(),
            format!("Eth Based {}", chaincode).as_str(),
        ))),
        CustomChainType::CustomSubstrate(_) => None,
        CustomChainType::CustomCosmos(_) => None,
    }
}

pub fn get_chain_by_base_id(base_id: u32) -> Option<Box<dyn Chain>> {
    ChainRegistry::new().get_chain_by_base_id(base_id)
}

pub fn get_chains() -> Vec<u32> {
    ChainRegistry::new().get_chains()
}

pub fn is_chain_supported(id: u32) -> bool {
    ChainRegistry::new().is_chain_supported(id)
}

pub fn get_supported_chains() -> Vec<u32> {
    ChainRegistry::new().get_supported_chains()
}

pub fn create_custom_evm(chain_id: u32) -> Option<Box<dyn Chain>> {
    ChainRegistry::new().create_custom_evm(chain_id)
}
