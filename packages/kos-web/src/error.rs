use kos::chains::ChainError;
use hex::FromHexError;
use std::{error, fmt, str};
use wasm_bindgen::JsValue;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KOSError {
    UnsupportedChain { id: String },
    KOSDelegate(String),
    HexDecode(String),
    KOSNumber(String),
    InvalidString(String),
    JSONSerde(String),
    InvalidMnemonic(String),
    InvalidPath(String),
    InvalidPrivateKey(String),
    InvalidPublicKey(String),
    InvalidAddress(String),
    InvalidChecksum(String),
    InvalidSignature(String),
    InvalidMessage(String),
    NotEnoughMemory(String),
    InvalidEnumVariant(String),
    InvalidLen(String),
    InvalidNumberParse(String),
    InvalidTransaction(String),
    WalletManager(String),
    Cipher(String),
    Transport(String),
}

impl fmt::Display for KOSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KOSError::UnsupportedChain { id } => write!(f, "UnsupportedChainError: Unsupported chain {id}"),
            KOSError::KOSDelegate(e) => write!(f, "KOSDelegateError: {e}"),
            KOSError::HexDecode(e) => write!(f, "HexDecodeError: {e}"),
            KOSError::KOSNumber(e) => write!(f, "KOSNumberError: {e}"),
            KOSError::InvalidString(e) => write!(f, "Invalid string: {e}"),
            KOSError::JSONSerde(e) => write!(f, "JSON serialization: {e}"),
            KOSError::InvalidMnemonic(e) => write!(f, "Invalid mnemonic: {e}"),
            KOSError::InvalidPath(e) => write!(f, "Invalid path: {e}"),
            KOSError::InvalidPrivateKey(e) => write!(f, "Invalid private key: {e}"),
            KOSError::InvalidPublicKey(e) => write!(f, "Invalid public key: {e}"),
            KOSError::InvalidAddress(e) => write!(f, "Invalid address: {e}"),
            KOSError::InvalidChecksum(e) => write!(f, "Invalid checksum: {e}"),
            KOSError::InvalidSignature(e) => write!(f, "Invalid signature: {e}"),
            KOSError::InvalidMessage(e) => write!(f, "Invalid message: {e}"),
            KOSError::NotEnoughMemory(e) => write!(f, "Not enough memory: {e}"),
            KOSError::InvalidEnumVariant(e) => write!(f, "Invalid Enum Variant error: {e}"),
            KOSError::InvalidLen(e) => write!(f, "Invalid Len: {e}"),
            KOSError::InvalidNumberParse(e) => write!(f, "Invalid number parse: {e}"),
            KOSError::InvalidTransaction(e) => write!(f, "Invalid transaction: {e}"),
            KOSError::WalletManager(e) => write!(f, "WalletManager error: {e}"),
            KOSError::Cipher(e) => write!(f, "Cipher error: {e}"),
            KOSError::Transport(e) => write!(f, "Transport error: {e}"),
        }
    }
}

impl From<ChainError> for KOSError {
    fn from(err: ChainError) -> Self {
        KOSError::KOSDelegate(err.to_string())
    }
}

impl From<FromHexError> for KOSError {
    fn from(err: FromHexError) -> Self {
        KOSError::HexDecode(err.to_string())
    }
}

impl From<serde_json::Error> for KOSError {
    fn from(e: serde_json::Error) -> Self {
        KOSError::JSONSerde(e.to_string())
    }
}

impl error::Error for KOSError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<KOSError> for JsValue {
    fn from(e: KOSError) -> Self {
        JsValue::from_str(&e.to_string())
    }
}
