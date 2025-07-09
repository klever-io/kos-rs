use kos::chains::ChainError;
use std::{error, fmt, str};
use wasm_bindgen::JsValue;

/// Crypto error variants
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Error {
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidString(e) => write!(f, "Invalid string: {e}"),
            Error::JSONSerde(e) => write!(f, "JSON serialization: {e}"),
            Error::UnsupportedChain(e) => write!(f, "Unsupported chain: {e}"),
            Error::InvalidMnemonic(e) => write!(f, "Invalid mnemonic: {e}"),
            Error::InvalidPath(e) => write!(f, "Invalid path: {e}"),
            Error::InvalidPrivateKey(e) => write!(f, "Invalid private key: {e}"),
            Error::InvalidPublicKey(e) => write!(f, "Invalid public key: {e}"),
            Error::InvalidAddress(e) => write!(f, "Invalid address: {e}"),
            Error::InvalidChecksum(e) => write!(f, "Invalid checksum: {e}"),
            Error::InvalidSignature(e) => write!(f, "Invalid signature: {e}"),
            Error::InvalidMessage(e) => write!(f, "Invalid message: {e}"),
            Error::NotEnoughMemory(e) => write!(f, "Not enough memory: {e}"),
            Error::InvalidEnumVariant(e) => write!(f, "Invalid Enum Variant error: {e}"),
            Error::InvalidLen(e) => write!(f, "Invalid Len: {e}"),
            Error::InvalidNumberParse(e) => write!(f, "Invalid number parse: {e}"),
            Error::InvalidTransaction(e) => write!(f, "Invalid transaction: {e}"),
            Error::WalletManager(e) => write!(f, "WalletManager error: {e}"),
            Error::Cipher(e) => write!(f, "Cipher error: {e}"),
            Error::Transport(e) => write!(f, "Transport error: {e}"),
            Error::Delegate(e) => write!(f, "Delegate error: {e}"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JSONSerde(e.to_string())
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<Error> for JsValue {
    fn from(e: Error) -> Self {
        JsValue::from_str(&format!("{e}"))
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidString(e.to_string())
    }
}

impl From<ChainError> for Error {
    fn from(err: ChainError) -> Self {
        Error::Delegate(err.to_string())
    }
}
