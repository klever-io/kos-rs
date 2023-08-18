// use crate::klever;
use kos_types::{error::Error, hash::Hash};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;

#[derive(Debug, Clone, Serialize)]
#[wasm_bindgen]
pub struct BroadcastResult {
    #[wasm_bindgen(skip)]
    pub tx: Transaction,
}

#[wasm_bindgen]
impl BroadcastResult {
    #[wasm_bindgen(constructor)]
    pub fn new(tx: Transaction) -> Self {
        Self { tx }
    }

    #[wasm_bindgen(js_name = hash)]
    pub fn hash(&self) -> Hash {
        self.tx.hash
    }

    #[allow(clippy::inherent_to_string)]
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
        Ethereum(super::chains::ETHTransaction),
        Polygon(super::chains::MATICTransaction),
        Bitcoin(super::chains::BTCTransaction),
    }
}

// create enum variant list of transaction types supported
kos_types::enum_thing! {
    enum Options {
        Klever(kos_proto::options::KLVOptions),
        Tron(kos_proto::options::TRXOptions),
        Ethereum(kos_proto::options::ETHOptions),
        Polygon(kos_proto::options::MATICOptions),
        Bitcoin(kos_proto::options::BTCOptions),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
/// Transaction Handler
pub struct SendOptions {
    #[wasm_bindgen(skip)]
    #[serde(skip)]
    pub data: Option<Options>,
}

impl SendOptions {
    pub fn new(data: Options) -> Self {
        Self { data: Some(data) }
    }
}

#[derive(Debug, Clone, Serialize)]
#[wasm_bindgen]
/// Transaction Handler
pub struct Transaction {
    #[wasm_bindgen(skip)]
    pub chain: Chain,
    #[wasm_bindgen(skip)]
    pub sender: String,
    #[wasm_bindgen(js_name = hash)]
    pub hash: Hash,
    #[wasm_bindgen(skip)]
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

    #[wasm_bindgen(js_name = getRaw)]
    pub fn get_raw(&self) -> Result<String, Error> {
        match &self.data {
            Some(data) => match data {
                TransactionRaw::Klever(data) => serde_json::to_string(&data).map_err(|e| e.into()),
                TransactionRaw::Tron(data) => serde_json::to_string(&data).map_err(|e| e.into()),
                TransactionRaw::Ethereum(data) => {
                    let encoded = data.encode()?;
                    Ok(hex::encode(encoded))
                }
                TransactionRaw::Polygon(data) => {
                    let encoded = data.eth.encode()?;
                    Ok(hex::encode(encoded))
                }
                TransactionRaw::Bitcoin(data) => {
                    serde_json::to_string(&data.tx).map_err(|e| e.into())
                }
            },
            None => Err(Error::InvalidTransaction("no data found".to_string())),
        }
    }
}

impl Transaction {
    pub fn new_data(&self, chain: Chain, data: TransactionRaw) -> Transaction {
        let mut tx = self.clone();
        tx.chain = chain;
        tx.data = Some(data);
        tx
    }
}
