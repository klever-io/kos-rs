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
mod movr;
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

impl From<tiny_json_rs::serializer::DecodeError> for ChainError {
    fn from(_: tiny_json_rs::serializer::DecodeError) -> Self {
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
        }
    }
}

pub enum TxType {
    Unknown,
    Transfer,
    TriggerContract,
}

impl tiny_json_rs::serializer::Serialize for TxType {
    fn serialize(&self) -> tiny_json_rs::mapper::Value {
        let str = match self {
            TxType::Unknown => "Unknown",
            TxType::Transfer => "Transfer",
            TxType::TriggerContract => "TriggerContract",
        };
        let token = Token {
            token_type: tiny_json_rs::lexer::TokenType::String(StringType::SimpleString),
            literal: str.to_string(),
        };

        tiny_json_rs::mapper::Value::Token(token)
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
}

#[allow(dead_code)]
impl Transaction {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            raw_data: Vec::new(),
            tx_hash: Vec::new(),
            signature: Vec::new(),
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

struct ChainRegistry {
    registry: &'static [(u32, ChainFactory)],
}

impl ChainRegistry {
    fn new() -> Self {
        static REGISTRY: [(u32, ChainFactory); 46] = [
            (constants::ETH, || Box::new(eth::ETH::new())),
            (constants::BSC, || {
                Box::new(eth::ETH::new_eth_based(26, 56, "BSC", "BnbSmartChain"))
            }),
            (constants::POLYGON, || {
                Box::new(eth::ETH::new_eth_based(28, 137, "MATIC", "Polygon"))
            }),
            (constants::HT, || {
                Box::new(eth::ETH::new_eth_based(30, 128, "HT", "Huobi"))
            }),
            (constants::SYS_NEVM, || {
                Box::new(eth::ETH::new_eth_based(37, 57, "SYS_NEVM", "Syscoin Nevm"))
            }),
            (constants::TRX, || Box::new(trx::TRX {})),
            (constants::KLV, || Box::new(klv::KLV {})),
            (constants::BTC, || Box::new(btc::BTC::new())),
            (constants::DOT, || {
                Box::new(substrate::Substrate::new(21, 0, "DOT", "Polkadot"))
            }),
            (constants::KSM, || {
                Box::new(substrate::Substrate::new(27, 2, "KSM", "Kusama"))
            }),
            (constants::LTC, || {
                Box::new(btc::BTC::new_btc_based(5, "ltc", "LTC", "Litecoin"))
            }),
            (constants::REEF, || {
                Box::new(substrate::Substrate::new(29, 42, "REEF", "Reef"))
            }),
            (constants::SDN, || {
                Box::new(substrate::Substrate::new(35, 5, "SDN", "Shiden"))
            }),
            (constants::ASTR, || {
                Box::new(substrate::Substrate::new(36, 5, "ASTR", "Astar"))
            }),
            (constants::CFG, || {
                Box::new(substrate::Substrate::new(47, 36, "CFG", "Centrifuge"))
            }),
            (constants::SYS, || {
                Box::new(btc::BTC::new_btc_based(15, "sys", "SYS", "Syscoin"))
            }),
            (constants::KILT, || {
                Box::new(substrate::Substrate::new(44, 38, "KILT", "KILT"))
            }),
            (constants::ALTAIR, || {
                Box::new(substrate::Substrate::new(42, 136, "ALTAIR", "Altair"))
            }),
            (constants::DOGE, || {
                Box::new(btc::BTC::new_legacy_btc_based(12, 0x1E, "DOGE", "Dogecoin"))
            }),
            (constants::DASH, || {
                Box::new(btc::BTC::new_legacy_btc_based(11, 0x4C, "DASH", "Dash"))
            }),
            (constants::XRP, || Box::new(xrp::XRP::new())),
            (constants::DGB, || {
                Box::new(btc::BTC::new_btc_based(16, "dgb", "DGB", "Digibyte"))
            }),
            (constants::COSMOS, || Box::new(atom::ATOM::new())),
            (constants::CELESTIA, || {
                Box::new(atom::ATOM::new_cosmos_based(
                    "celestia", "celestia", "Celestia", "TIA",
                ))
            }),
            (constants::CUDOS, || {
                Box::new(atom::ATOM::new_cosmos_based(
                    "cudos", "cudos-1", "Cudos", "CUDOS",
                ))
            }),
            (constants::AURA, || {
                Box::new(atom::ATOM::new_cosmos_based(
                    "aura", "xstaxy-1", "Aura", "AURA",
                ))
            }),
            (constants::ICP, || Box::new(icp::ICP {})),
            (constants::SOL, || Box::new(sol::SOL {})),
            (constants::MOVR, || Box::new(movr::MOVR::new())),
            (constants::GLMR, || Box::new(movr::MOVR::new_glmr())),
            (constants::BNB, || Box::new(bnb::BNB {})),
            (constants::BCH, || Box::new(bch::BCH {})),
            (constants::ADA, || Box::new(ada::ADA {})),
            (constants::SUI, || Box::new(sui::SUI {})),
            (constants::APT, || Box::new(apt::APT {})),
            (constants::AVAIL, || {
                Box::new(substrate::Substrate::new(62, 42, "AVAIL", "Avail"))
            }),
            (constants::ROLLUX, || {
                Box::new(eth::ETH::new_eth_based(63, 570, "ROLLUX", "Rollux"))
            }),
            (constants::AVAX, || {
                Box::new(eth::ETH::new_eth_based(39, 43114, "AVAX", "Avalanche"))
            }),
            (constants::ARB, || {
                Box::new(eth::ETH::new_eth_based(57, 42161, "ARB", "Arbitrum"))
            }),
            (constants::BASE, || {
                Box::new(eth::ETH::new_eth_based(60, 8453, "BASE", "Base"))
            }),
            (constants::NEAR, || {
                Box::new(eth::ETH::new_eth_based(64, 397, "NEAR", "Near"))
            }),
            (constants::FTM, || {
                Box::new(eth::ETH::new_eth_based(54, 250, "FTM", "Fantom"))
            }),
            (constants::CHZ, || {
                Box::new(eth::ETH::new_eth_based(61, 88888, "CHZ", "Chiliz"))
            }),
            (constants::OP, || {
                Box::new(eth::ETH::new_eth_based(53, 10, "OP", "Optimism"))
            }),
            (constants::POLYGON_ZKEVM, || {
                Box::new(eth::ETH::new_eth_based(52, 1101, "ZKEVM", "Polygon zkEVM"))
            }),
            (constants::STOLZ, || {
                Box::new(eth::ETH::new_eth_based(67, 2344, "STOLZ", "Stolz"))
            }),
        ];

        Self {
            registry: &REGISTRY,
        }
    }

    fn get_chain_by_id(&self, id: u32) -> Option<Box<dyn Chain>> {
        for &(chain_id, factory) in self.registry {
            if chain_id == id {
                return Some(factory());
            }
        }
        None
    }

    fn get_chain_by_base_id(&self, base_id: u32) -> Option<Box<dyn Chain>> {
        for &(_, factory) in self.registry {
            let chain = factory();
            if chain.get_id() == base_id {
                return Some(chain);
            }
        }
        None
    }

    fn get_chains(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for &(_, factory) in self.registry {
            let chain = factory();
            ids.push(chain.get_id());
        }
        ids
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
    return match params {
        CustomChainType::NotCustom(c) => get_chain_by_id(c),
        CustomChainType::CustomEth(chaincode) => Some(Box::new(eth::ETH::new_eth_based(
            0,
            chaincode,
            format!("ETH {}", chaincode).as_str(),
            format!("Eth Based {}", chaincode).as_str(),
        ))),
        CustomChainType::CustomSubstrate(_) => None,
        CustomChainType::CustomCosmos(_) => None,
    };
}

pub fn get_chain_by_base_id(base_id: u32) -> Option<Box<dyn Chain>> {
    ChainRegistry::new().get_chain_by_base_id(base_id)
}

pub fn get_chains() -> Vec<u32> {
    ChainRegistry::new().get_chains()
}
