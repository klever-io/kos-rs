use crate::ed25519;
use crate::secp256k1;

use std::fmt;

use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum KeyType {
    Default,
    Ed25519,
    Secp256k1,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[wasm_bindgen]
pub struct KeyPair {
    key_type: KeyType,
    ed25519: Option<ed25519::Ed25519KeyPair>,
    secp256k1: Option<secp256k1::Secp256k1KeyPair>,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn new_default() -> Self {
        Self {
            key_type: KeyType::Default,
            ed25519: None,
            secp256k1: None,
        }
    }

    pub fn new_ed25519(kp: ed25519::Ed25519KeyPair) -> Self {
        Self {
            key_type: KeyType::Ed25519,
            ed25519: Some(kp),
            secp256k1: None,
        }
    }

    pub fn new_secp256k1(kp: secp256k1::Secp256k1KeyPair) -> Self {
        Self {
            key_type: KeyType::Secp256k1,
            ed25519: None,
            secp256k1: Some(kp),
        }
    }
}

impl KeyPair {
    pub fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        match self.key_type {
            KeyType::Default => Vec::new(),
            KeyType::Ed25519 => self.ed25519.as_ref().unwrap().sign_digest(digest),
            KeyType::Secp256k1 => self.secp256k1.as_ref().unwrap().sign_digest(digest),
        }
    }
}

impl From<ed25519::Ed25519KeyPair> for KeyPair {
    fn from(kp: ed25519::Ed25519KeyPair) -> Self {
        Self::new_ed25519(kp)
    }
}

impl From<secp256k1::Secp256k1KeyPair> for KeyPair {
    fn from(kp: secp256k1::Secp256k1KeyPair) -> Self {
        Self::new_secp256k1(kp)
    }
}

impl KeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        match self.key_type {
            KeyType::Default => Vec::new(),
            KeyType::Ed25519 => self.ed25519.as_ref().unwrap().public_key(),
            KeyType::Secp256k1 => self.secp256k1.as_ref().unwrap().public_key(),
        }
    }

    pub fn public_key_hex(&self) -> String {
        let bytes = self.public_key();
        hex::encode(bytes)
    }

    pub fn secret_key(&self) -> Vec<u8> {
        match self.key_type {
            KeyType::Default => Vec::new(),
            KeyType::Ed25519 => self.ed25519.as_ref().unwrap().secret_key(),
            KeyType::Secp256k1 => self.secp256k1.as_ref().unwrap().secret_key(),
        }
    }

    pub fn secret_key_hex(&self) -> String {
        let bytes = self.secret_key();
        hex::encode(bytes)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.key_type)
            .field(&self.ed25519)
            .field(&self.secp256k1)
            .finish()
    }
}
