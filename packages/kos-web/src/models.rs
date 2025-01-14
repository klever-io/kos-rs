use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
#[wasm_bindgen]
pub struct PathOptions {
    #[wasm_bindgen(skip)]
    pub index: u32,
    #[wasm_bindgen(skip)]
    pub is_legacy: Option<bool>,
}

#[wasm_bindgen]
impl PathOptions {
    #[wasm_bindgen(constructor)]
    pub fn constructor() -> Self {
        Self::default()
    }

    pub fn new(index: u32) -> Self {
        Self {
            index,
            is_legacy: Some(false),
        }
    }
    #[wasm_bindgen(js_name = setIndex)]
    pub fn set_index(&mut self, index: u32) {
        self.index = index;
    }
    #[wasm_bindgen(js_name = setLegacy)]
    pub fn set_legacy(&mut self, is_legacy: bool) {
        self.is_legacy = Some(is_legacy);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Transaction {
    #[wasm_bindgen(skip)]
    pub raw_data: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub tx_hash: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub signature: Vec<u8>,
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(js_name = getRawData)]
    pub fn get_raw_data(&self) -> Vec<u8> {
        self.raw_data.clone()
    }

    #[wasm_bindgen(js_name = getTxHash)]
    pub fn get_tx_hash(&self) -> Vec<u8> {
        self.tx_hash.clone()
    }

    #[wasm_bindgen(js_name = getSignature)]
    pub fn get_signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}
