use kos::chains::ChainError;
use std::{error, fmt};
use wasm_bindgen::prelude::*;

// Rust-only error type with associated data
#[derive(Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct KOSError {
    #[wasm_bindgen(skip)]
    pub message: String,
}

#[wasm_bindgen]
impl KOSError {
    #[wasm_bindgen(constructor)]
    pub fn new(message: String) -> KOSError {
        KOSError { message }
    }

    #[wasm_bindgen(js_name = getMessage)]
    pub fn get_message(&self) -> String {
        self.message.clone()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.message.clone()
    }
}

impl KOSError {
    pub fn unsupported_chain(id: String) -> Self {
        KOSError {
            message: format!("UnsupportedChainError: Unsupported chain {id}"),
        }
    }

    pub fn kos_delegate(msg: String) -> Self {
        KOSError {
            message: format!("KOSDelegateError: {msg}"),
        }
    }

    pub fn hex_decode(msg: String) -> Self {
        KOSError {
            message: format!("HexDecodeError: {msg}"),
        }
    }

    pub fn kos_number(msg: String) -> Self {
        KOSError {
            message: format!("KOSNumberError: {msg}"),
        }
    }

    pub fn invalid_string(msg: String) -> Self {
        KOSError {
            message: format!("Invalid string: {msg}"),
        }
    }

    pub fn json_serde(msg: String) -> Self {
        KOSError {
            message: format!("JSON serialization: {msg}"),
        }
    }

    pub fn invalid_mnemonic(msg: String) -> Self {
        KOSError {
            message: format!("Invalid mnemonic: {msg}"),
        }
    }

    pub fn wallet_manager(msg: String) -> Self {
        KOSError {
            message: format!("WalletManager error: {msg}"),
        }
    }

    pub fn cipher(msg: String) -> Self {
        KOSError {
            message: format!("Cipher error: {msg}"),
        }
    }
}

impl fmt::Display for KOSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<serde_json::Error> for KOSError {
    fn from(e: serde_json::Error) -> Self {
        KOSError::json_serde(e.to_string())
    }
}

impl error::Error for KOSError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<hex::FromHexError> for KOSError {
    fn from(e: hex::FromHexError) -> Self {
        KOSError::hex_decode(e.to_string())
    }
}

impl From<ChainError> for KOSError {
    fn from(err: ChainError) -> Self {
        KOSError::kos_delegate(err.to_string())
    }
}
