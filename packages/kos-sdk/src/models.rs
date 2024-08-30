use pbjson::private::base64;
// use crate::klever;
use kos_types::{error::Error, hash::Hash};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::chain::Chain;
use crate::chain::Chain::KLV;

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
        let mut sender = String::default();

        let data = match chain {
            Chain::KLV => {
                let tx: kos_proto::klever::Transaction =
                    serde_json::from_str(data).expect("failed to parse klever transaction");

                // unwrap raw_data
                let raw_data = tx
                    .raw_data
                    .clone()
                    .ok_or_else(|| Error::InvalidTransaction("no raw TX found".to_string())).unwrap();

                sender = String::default();
                TransactionRaw::Klever(tx)
            }
            Chain::TRX => {
                let tx: kos_proto::tron::Transaction =
                    serde_json::from_str(data).unwrap();

                let raw_data = &tx.clone().raw_data.unwrap().contract[0];

                let value = &raw_data.parameter.clone().unwrap().value;


                sender = String::default();
                TransactionRaw::Tron(tx)
            }

            Chain::ETH => {
                let data: super::chains::ETHTransaction =
                    serde_json::from_str(data).expect("failed to parse ethereum transaction");
                TransactionRaw::Ethereum(data)
            }
            Chain::MATIC => {
                todo!("decode polygon transaction")
            }
            Chain::BTC => {
               todo!("decode bitcoin transaction")
            }
            Chain::NONE => {
                panic!("invalid chain")
            }
        };

        let hash = Hash::default();

        Self {
            chain,
            sender,
            hash,
            data: Some(data),
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

// Test Transaction from raw
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::ETHTransaction;
    use kos_proto::klever::Transaction as KleverTransaction;
    use kos_proto::tron::Transaction as TronTransaction;
    use serde_json::json;
    use web3::ethabi::ParamType::String;

    #[test]
    fn test_transaction_from_raw() {


        let tron_tx_str = r#"{"raw_data":{"ref_block_bytes":"ceda","ref_block_hash":"55821ec130fa833c","expiration":1725055080000,"contract":[{"type":"TransferContract","parameter":{"typeUrl":"type.googleapis.com/protocol.TransferContract","value":"ChVBBYOmijvNhsJasb7kgrrASiFrAmESFUHIWZER8pweHgYSZbSvk+ofJ0rXihgK"}}],"timestamp":1725055023434}}"#;
        let klv_tx_str = r#"{"RawData":{"Nonce":312,"Sender":"nxNUcG11rraE8m196h+9oX4mTHWVzB7d7AuJaMG+hSQ=","Contract":[{"Parameter":{"type_url":"type.googleapis.com/proto.TransferContract","value":"CiCthZSJePbX7pPJ64gh6PZ+HBo1YPZddPMYyYs/+aLSMxIDS0xWGMCEPQ=="}}],"Data":[""],"KAppFee":1000000,"BandwidthFee":2000000,"Version":1,"ChainID":"MTA4"}}"#;

        let tx = Transaction::from_raw(Chain::TRX, tron_tx_str);

        assert_eq!(tx.chain, Chain::TRX);

    }
}
