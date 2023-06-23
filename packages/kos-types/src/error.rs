use core::convert::Infallible;
use ed25519_dalek::SignatureError;
use reqwest::Error as ReqwestError;
use secp256k1::Error as Secp256k1Error;
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
    UnsupportedChain(&'static str),
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
    /// Reqwest error
    ReqwestError(String),
    /// Invalid Enum Variant
    InvalidEnumVariant(String),
    /// Invalid Len
    InvalidLen(String),
    /// InvalidNumberParse
    InvalidNumberParse(String),
    /// InvalidTransaction
    InvalidTransaction(String),
    /// WalletManagerError
    WalletManagerError(String),
    /// CipherError
    CipherError(String),
    /// TransportError
    TransportError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidString(e) => write!(f, "Invalid string: {}", e),
            Error::JSONSerde(e) => write!(f, "JSON serialization: {}", e),
            Error::UnsupportedChain(e) => write!(f, "Unsupported chain: {}", e),
            Error::InvalidMnemonic(e) => write!(f, "Invalid mnemonic: {}", e),
            Error::InvalidPath(e) => write!(f, "Invalid path: {}", e),
            Error::InvalidPrivateKey(e) => write!(f, "Invalid private key: {}", e),
            Error::InvalidPublicKey(e) => write!(f, "Invalid public key: {}", e),
            Error::InvalidAddress(e) => write!(f, "Invalid address: {}", e),
            Error::InvalidChecksum(e) => write!(f, "Invalid checksum: {}", e),
            Error::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            Error::InvalidMessage(e) => write!(f, "Invalid message: {}", e),
            Error::NotEnoughMemory(e) => write!(f, "Not enough memory: {}", e),
            Error::ReqwestError(e) => write!(f, "Reqwest error: {}", e),
            Error::InvalidEnumVariant(e) => write!(f, "Invalid Enum Variant error: {}", e),
            Error::InvalidLen(e) => write!(f, "Invalid Len: {}", e),
            Error::InvalidNumberParse(e) => write!(f, "Invalid number parse: {}", e),
            Error::InvalidTransaction(e) => write!(f, "Invalid transaction: {}", e),
            Error::WalletManagerError(e) => write!(f, "WalletManager error: {}", e),
            Error::CipherError(e) => write!(f, "Cipher error: {}", e),
            Error::TransportError(e) => write!(f, "Transport error: {}", e),
        }
    }
}

impl From<Secp256k1Error> for Error {
    fn from(secp: Secp256k1Error) -> Self {
        match secp {
            Secp256k1Error::IncorrectSignature
            | Secp256k1Error::InvalidSignature
            | Secp256k1Error::InvalidTweak
            | Secp256k1Error::InvalidSharedSecret
            | Secp256k1Error::InvalidPublicKeySum
            | Secp256k1Error::InvalidParityValue(_)
            | Secp256k1Error::InvalidRecoveryId => Self::InvalidSignature("Secp256k1Error"),
            Secp256k1Error::InvalidMessage => Self::InvalidMessage(secp.to_string()),
            Secp256k1Error::InvalidPublicKey => Self::InvalidPublicKey(secp.to_string()),
            Secp256k1Error::InvalidSecretKey => Self::InvalidPrivateKey("Secp256k1Error"),
            Secp256k1Error::NotEnoughMemory => Self::NotEnoughMemory(secp.to_string()),
        }
    }
}

impl From<SignatureError> for Error {
    fn from(_: SignatureError) -> Self {
        Self::InvalidSignature("Invalid signature")
    }
}

impl From<coins_bip39::MnemonicError> for Error {
    fn from(_: coins_bip39::MnemonicError) -> Self {
        Self::InvalidMnemonic("Invalid mnemonic")
    }
}

impl From<coins_bip32::Bip32Error> for Error {
    fn from(_: coins_bip32::Bip32Error) -> Self {
        Self::InvalidPath("Invalid path")
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
        JsValue::from_str(&format!("{}", e))
    }
}

impl From<ReqwestError> for Error {
    fn from(e: ReqwestError) -> Self {
        Self::ReqwestError(e.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidString(e.to_string())
    }
}

impl From<Error> for Infallible {
    fn from(_: Error) -> Infallible {
        unreachable!()
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Error {
        unreachable!()
    }
}
