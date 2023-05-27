// use crate::klever;
use kos_types::{error::Error, hash::Hash};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BroadcastResult {
    #[wasm_bindgen(skip)]
    pub tx: Transaction,
}

#[wasm_bindgen]
impl BroadcastResult {
    #[wasm_bindgen(constructor)]
    pub fn new(tx: Transaction) -> Self {
        Self { tx: tx }
    }

    #[wasm_bindgen(js_name = hash)]
    pub fn hash(&self) -> Hash {
        self.tx.hash.clone()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

// create enum variant list of transaction types supported
kos_types::enum_thing! {
    enum TransactionRaw {
        Klever(kos_proto::klever::Transaction),
        Tron(kos_proto::tron::Transaction),
    }
}

// create enum variant list of transaction types supported
kos_types::enum_thing! {
    enum Options {
        Klever(kos_proto::options::KLVOptions),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
/// Transcation Handler
pub struct SendOptions {
    #[wasm_bindgen(skip)]
    #[serde(skip)]
    pub data: Option<Options>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
/// Transcation Handler
pub struct Transaction {
    #[wasm_bindgen(skip)]
    pub chain: Chain,
    #[wasm_bindgen(js_name = hash)]
    pub hash: Hash,
    #[wasm_bindgen(skip)]
    // TODO!()
    #[serde(skip)]
    pub data: Option<TransactionRaw>,
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(js_name = chain)]
    pub fn chain(&self) -> Chain {
        self.chain
    }
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(|e| e.into())
    }
}
