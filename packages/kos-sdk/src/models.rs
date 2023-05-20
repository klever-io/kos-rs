use kos_types::hash::Hash;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BroadcastResult {
    hash: Hash,
    raw: Vec<u8>,
}

#[wasm_bindgen]
impl BroadcastResult {
    #[wasm_bindgen(constructor)]
    pub fn new(hash: Hash, raw: Vec<u8>) -> Self {
        Self { hash, raw }
    }

    pub fn hash(&self) -> Hash {
        self.hash.clone()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    chain: Chain,
    hash: String,
    raw: Vec<u8>,
}

#[wasm_bindgen]
impl Transaction {}
