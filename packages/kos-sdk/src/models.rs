use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BroadcastResult {
    hash: String,
    raw: Vec<u8>,
}

#[wasm_bindgen]
impl BroadcastResult {
    pub fn new(hash: String, raw: Vec<u8>) -> Self {
        Self { hash, raw }
    }

    pub fn hash(&self) -> String {
        self.hash.clone()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }
}
