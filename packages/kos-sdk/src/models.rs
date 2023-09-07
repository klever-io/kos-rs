// use crate::klever;
use kos_types::{error::Error, hash::Hash, number::BigNumber};
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

#[wasm_bindgen]
impl SendOptions {
    #[wasm_bindgen(js_name = newKleverSendOptions)]
    pub fn new_klever_send_options(
        nonce: Option<u64>,
        kda: Option<String>,
        kda_royalties: Option<i64>,
        kda_fee: Option<String>,
        memo: Option<String>,
    ) -> Self {
        let memo = match memo {
            Some(memo) => Some(vec![memo]),
            None => None,
        };

        Self {
            data: Some(Options::Klever(kos_proto::options::KLVOptions {
                nonce,
                kda,
                kda_royalties,
                kda_fee,
                memo,
            })),
        }
    }

    #[wasm_bindgen(js_name = newTronSendOptions)]
    pub fn new_tron_send_options(
        token: Option<String>,
        fee_limit: Option<i64>,
        memo: Option<String>,
    ) -> Self {
        Self {
            data: Some(Options::Tron(kos_proto::options::TRXOptions {
                token,
                fee_limit,
                memo,
            })),
        }
    }

    #[wasm_bindgen(js_name = newEthereumSendOptions)]
    pub fn new_ethereum_send_options(
        legacy_type: Option<bool>,
        nonce: Option<u64>,
        chain_id: Option<u64>,
        token: Option<String>,
        gas_limit: Option<BigNumber>,
        gas_price: Option<BigNumber>,
        contract_data: Option<Vec<u8>>,
        max_fee_per_gas: Option<BigNumber>,
        max_priority_fee_per_gas: Option<BigNumber>,
    ) -> Self {
        Self {
            data: Some(Options::Ethereum(kos_proto::options::ETHOptions {
                legacy_type,
                nonce,
                chain_id,
                token,
                gas_limit,
                gas_price,
                contract_data,
                max_fee_per_gas,
                max_priority_fee_per_gas,
            })),
        }
    }

    #[wasm_bindgen(js_name = newPolygonSendOptions)]
    pub fn new_polygon_send_options(
        legacy_type: Option<bool>,
        nonce: Option<u64>,
        chain_id: Option<u64>,
        token: Option<String>,
        gas_limit: Option<BigNumber>,
        gas_price: Option<BigNumber>,
        contract_data: Option<Vec<u8>>,
        max_fee_per_gas: Option<BigNumber>,
        max_priority_fee_per_gas: Option<BigNumber>,
    ) -> Self {
        Self {
            data: Some(Options::Polygon(kos_proto::options::MATICOptions {
                eth: kos_proto::options::ETHOptions {
                    legacy_type,
                    nonce,
                    chain_id,
                    token,
                    gas_limit,
                    gas_price,
                    contract_data,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                },
            })),
        }
    }

    #[wasm_bindgen(js_name = newBitcoinSendOptions)]
    pub fn new_bitcoin_send_options(
        network: Option<String>,
        sats_per_bytes: Option<u64>,
        dust_value: Option<BigNumber>,
        send_all: Option<bool>,
        change_address: Option<String>,
        rbf: Option<bool>,
    ) -> Self {
        Self {
            data: Some(Options::Bitcoin(kos_proto::options::BTCOptions {
                network,
                sats_per_bytes,
                dust_value,
                send_all,
                change_address,
                receivers: None,
                rbf,
            })),
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
