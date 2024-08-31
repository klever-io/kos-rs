use crate::chain::Chain;
use crate::chains::{ETH, KLV, TRX};
use kos_types::{error::Error, hash::Hash};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

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

#[wasm_bindgen]
impl SendOptions {
    #[wasm_bindgen(js_name = newKleverSendOptions)]
    pub fn new_klever_send_options(option: kos_proto::options::KLVOptions) -> Self {
        Self {
            data: Some(Options::Klever(option)),
        }
    }

    #[wasm_bindgen(js_name = newTronSendOptions)]
    pub fn new_tron_send_options(option: kos_proto::options::TRXOptions) -> Self {
        Self {
            data: Some(Options::Tron(option)),
        }
    }

    #[wasm_bindgen(js_name = newEthereumSendOptions)]
    pub fn new_ethereum_send_options(option: &kos_proto::options::ETHOptions) -> Self {
        Self {
            data: Some(Options::Ethereum(option.clone())),
        }
    }

    #[wasm_bindgen(js_name = newPolygonSendOptions)]
    pub fn new_polygon_send_options(option: &kos_proto::options::MATICOptions) -> Self {
        Self {
            data: Some(Options::Polygon(option.clone())),
        }
    }

    #[wasm_bindgen(js_name = newBitcoinSendOptions)]
    pub fn new_bitcoin_send_options(option: &kos_proto::options::BTCOptions) -> Self {
        Self {
            data: Some(Options::Bitcoin(option.clone())),
        }
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

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(js_name = fromRaw)]
    pub fn from_raw(chain: Chain, data: &str) -> Self {
        match chain {
            Chain::KLV => KLV::tx_from_raw(data).unwrap(),
            Chain::TRX => TRX::tx_from_raw(data).unwrap(),
            Chain::ETH => ETH::tx_from_json(data).unwrap(),
            Chain::MATIC => {
                todo!()
            }
            Chain::BTC => {
                todo!()
            }
            Chain::NONE => {
                panic!("Invalid Chain")
            }
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct AddressOptions {
    #[wasm_bindgen(skip)]
    pub network: Option<String>,
    #[wasm_bindgen(skip)]
    pub prefix: Option<String>,
    #[wasm_bindgen(skip)]
    pub check_summed: Option<bool>,
}

#[wasm_bindgen]
impl AddressOptions {
    pub fn new(
        network: Option<String>,
        prefix: Option<String>,
        check_summed: Option<bool>,
    ) -> Self {
        Self {
            network,
            prefix,
            check_summed,
        }
    }

    #[wasm_bindgen(js_name = setNetwork)]
    pub fn set_network(&mut self, network: Option<String>) {
        self.network = network;
    }

    #[wasm_bindgen(js_name = setPrefix)]
    pub fn set_prefix(&mut self, prefix: Option<String>) {
        self.prefix = prefix;
    }

    #[wasm_bindgen(js_name = setCheckSummed)]
    pub fn set_check_summed(&mut self, check_summed: Option<bool>) {
        self.check_summed = check_summed;
    }

    #[wasm_bindgen(js_name = getNetwork)]
    pub fn get_network(&self) -> Option<String> {
        self.network.clone()
    }

    #[wasm_bindgen(js_name = getPrefix)]
    pub fn get_prefix(&self) -> Option<String> {
        self.prefix.clone()
    }

    #[wasm_bindgen(js_name = getCheckSummed)]
    pub fn get_check_summed(&self) -> Option<bool> {
        self.check_summed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_from_raw() {
        let klv_tx_str = r#"{"RawData":{"Nonce":312,"Sender":"nxNUcG11rraE8m196h+9oX4mTHWVzB7d7AuJaMG+hSQ=","Contract":[{"Parameter":{"type_url":"type.googleapis.com/proto.TransferContract","value":"CiCthZSJePbX7pPJ64gh6PZ+HBo1YPZddPMYyYs/+aLSMxIDS0xWGMCEPQ=="}}],"Data":[""],"KAppFee":1000000,"BandwidthFee":2000000,"Version":1,"ChainID":"MTA4"}}"#;

        let klv_tx = Transaction::from_raw(Chain::KLV, klv_tx_str);

        assert_eq!(
            klv_tx.sender,
            "klv1nuf4gurdwkhtdp8jd47758aa59lzvnr4jhxpah0vpwyk3sd7s5jqy6mut7"
        );

        let tron_tx_str = "0a02d8372208e9c73b516bcd78844088c6e8ad9a325a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed662618c0843d70fdfee4ad9a32";

        let tron_tx = Transaction::from_raw(Chain::TRX, tron_tx_str);

        assert_eq!(tron_tx.sender, "TX8h6Df74VpJsXF6sTDz1QJsq3Ec8dABc3");

        let eth_tx_str = r#"{
        "from":"0x4cbeee256240c92a9ad920ea6f4d7df6466d2cdc",
        "maxPriorityFeePerGas":null,"maxFeePerGas":null,
         "gas": "0x00",
         "value": "0x00",
         "data":"0xa9059cbb000000000000000000000000ac4145fef6c828e8ae017207ad944c988ccb2cf700000000000000000000000000000000000000000000000000000000000f4240",
         "to":"0xdac17f958d2ee523a2206206994597c13d831ec7",
         "nonce":"0x00"}"#;

        let eth_tx = Transaction::from_raw(Chain::ETH, eth_tx_str);

        assert_eq!(eth_tx.sender, "0x4cBeee256240c92A9ad920ea6f4d7Df6466D2Cdc");
    }
}
