use kos::chains::ChainError;
use std::{error, fmt, str};
use wasm_bindgen::JsValue;

/// Crypto error variants
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KosError {
    // Invalid string
    InvalidString(String),
    // JSON serialization error
    JSONSerde(String),
    // UnsupportedChain,
    UnsupportedChain(String),
    // InvalidMnemonic,
    InvalidMnemonic(&'static str),
    // InvalidPath,
    InvalidPath(&'static str),
    // InvalidPrivateKey,
    InvalidPrivateKey(&'static str),
    // InvalidPublicKey,
    InvalidPublicKey(String),
    // InvalidAddress,
    InvalidAddress(String),
    // InvalidChecksum,
    InvalidChecksum(&'static str),
    /// Invalid secp256k1 signature
    InvalidSignature(&'static str),
    /// Invalid secp256k1 signature message
    InvalidMessage(String),
    /// Out of preallocated memory
    NotEnoughMemory(String),
    /// Invalid Enum Variant
    InvalidEnumVariant(String),
    /// Invalid Len
    InvalidLen(String),
    /// InvalidNumberParse
    InvalidNumberParse(String),
    /// InvalidTransaction
    InvalidTransaction(String),
    /// WalletManagerError
    WalletManager(String),
    /// CipherError
    Cipher(String),
    /// TransportError
    Transport(String),
    /// DelegateError
    Delegate(String),
}

impl fmt::Display for KosError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KosError::InvalidString(e) => write!(f, "Invalid string: {e}"),
            KosError::JSONSerde(e) => write!(f, "JSON serialization: {e}"),
            KosError::UnsupportedChain(e) => write!(f, "Unsupported chain: {e}"),
            KosError::InvalidMnemonic(e) => write!(f, "Invalid mnemonic: {e}"),
            KosError::InvalidPath(e) => write!(f, "Invalid path: {e}"),
            KosError::InvalidPrivateKey(e) => write!(f, "Invalid private key: {e}"),
            KosError::InvalidPublicKey(e) => write!(f, "Invalid public key: {e}"),
            KosError::InvalidAddress(e) => write!(f, "Invalid address: {e}"),
            KosError::InvalidChecksum(e) => write!(f, "Invalid checksum: {e}"),
            KosError::InvalidSignature(e) => write!(f, "Invalid signature: {e}"),
            KosError::InvalidMessage(e) => write!(f, "Invalid message: {e}"),
            KosError::NotEnoughMemory(e) => write!(f, "Not enough memory: {e}"),
            KosError::InvalidEnumVariant(e) => write!(f, "Invalid Enum Variant error: {e}"),
            KosError::InvalidLen(e) => write!(f, "Invalid Len: {e}"),
            KosError::InvalidNumberParse(e) => write!(f, "Invalid number parse: {e}"),
            KosError::InvalidTransaction(e) => write!(f, "Invalid transaction: {e}"),
            KosError::WalletManager(e) => write!(f, "WalletManager error: {e}"),
            KosError::Cipher(e) => write!(f, "Cipher error: {e}"),
            KosError::Transport(e) => write!(f, "Transport error: {e}"),
            KosError::Delegate(e) => write!(f, "Delegate error: {e}"),
        }
    }
}

impl From<serde_json::Error> for KosError {
    fn from(e: serde_json::Error) -> Self {
        Self::JSONSerde(e.to_string())
    }
}

impl error::Error for KosError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<KosError> for JsValue {
    fn from(e: KosError) -> Self {
        JsValue::from_str(&format!("{e}"))
    }
}

impl From<hex::FromHexError> for KosError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidString(e.to_string())
    }
}

impl From<ChainError> for KosError {
    fn from(err: ChainError) -> Self {
        KosError::Delegate(err.to_string())
    }
}
