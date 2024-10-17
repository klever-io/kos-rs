use crate::chains::*;
use crate::models::{self, BroadcastResult, PathOptions, Transaction};
use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::{EnumCount, IntoStaticStr};

use wasm_bindgen::prelude::*;

macro_rules! createChains {
    ($($name:ident),*) => {
        #[wasm_bindgen]
        #[derive(Serialize, Deserialize, PartialEq, Debug, Copy, Clone, EnumCount, IntoStaticStr)]
        pub enum Chain {
            $($name,)*
        }

        lazy_static! {
            static ref CHAIN_MAP: HashMap<u8, Chain> = {
                let mut map = HashMap::new();
                $(map.insert($name::base_chain().chain_code, Chain::$name);)*
                // remove the NONE chain
                map.remove(&0);
                map
            };
        }

        impl Chain {
            pub fn base_chain(&self) -> BaseChain {
                match self {
                    $(Chain::$name => $name::base_chain(),)*
                }
            }

            pub fn new_keypair(&self) -> Result<KeyPair, Error> {
                match self {
                    $(Chain::$name => $name::random(),)*
                }
            }

            pub fn keypair_from_bytes(&self, private_key: &[u8]) -> Result<KeyPair, Error> {
                match self {
                    $(Chain::$name => $name::keypair_from_bytes(private_key),)*
                }
            }

            pub fn keypair_from_mnemonic(&self, mnemonic: &str, path: &str, password: Option<String>) -> Result<KeyPair, Error> {
                match self {
                    $(Chain::$name => $name::keypair_from_mnemonic(mnemonic, path, password),)*
                }
            }

            pub fn get_address_from_keypair(&self, privatekey: &KeyPair) -> Result<String, Error> {
                match self {
                    $(Chain::$name => $name::get_address_from_keypair(privatekey),)*
                }
            }

            pub fn get_path(&self, options: &PathOptions) -> Result<String, Error> {
                match self {
                    $(Chain::$name => $name::get_path(options),)*
                }
            }

            pub fn get_by_code(code: u8) -> Option<Self> {
                CHAIN_MAP.get(&code).cloned()
            }

            pub fn get_chains() -> HashMap<u8, Chain> {
                CHAIN_MAP.clone()
            }

            /// Sign digest data with the private key.
            pub fn sign_digest(&self, digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
                match self {
                    $(Chain::$name => $name::sign_digest(digest, keypair),)*
                }
            }

            /// Verify Message signature
            pub fn verify_digest(&self, digest: &[u8], signature: &[u8], address: &str) -> Result<bool, Error> {
                match self {
                    $(Chain::$name => $name::verify_digest(digest, signature, address),)*
                }
            }

            /// Hash and Sign data with the private key.
            pub fn sign(&self, data: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
                match self {
                    $(Chain::$name => $name::sign(data, keypair),)*
                }
            }

            /// Append prefix and hash the message
            pub fn message_hash(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                match self {
                    $(Chain::$name => $name::message_hash(message),)*
                }
            }

            /// Sign Message with the private key.
            pub fn sign_message(&self, message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
                match self {
                    $(Chain::$name => $name::sign_message(message, keypair),)*
                }
            }

            /// Verify Message signature
            pub fn verify_message_signature(&self, message: &[u8], signature: &[u8], address: &str) -> Result<bool, Error> {
                match self {
                    $(Chain::$name => $name::verify_message_signature(message, signature, address),)*
                }
            }

            /// Get balance of address and token
            /// If token is None, it will return balance of native token
            /// If token is Some, it will return balance of token
            /// If node_url is None, it will use default node url
            pub async fn get_balance(&self, address: &str, token: Option<String>, node_url: Option<String>) -> Result<BigNumber, Error> {
                match self {
                    $(Chain::$name => $name::get_balance(address, token, node_url).await,)*
                }
            }

            pub async fn send(
                &self,
                sender: String,
                receiver: String,
                amount: BigNumber,
                options: Option<models::SendOptions>,
                node_url: Option<String>,
            ) -> Result<Transaction, Error> {
                match self {
                    $(Chain::$name => $name::send(sender, receiver, amount, options, node_url).await,)*
                }
            }

            pub async fn broadcast(&self, data: Transaction, node_url: Option<String>) -> Result<BroadcastResult, Error> {
                match self {
                    $(Chain::$name => $name::broadcast(data, node_url).await,)*
                }
            }

            /// validate chain address format with options
            pub fn validate_address(&self, address: &str, option: Option<models::AddressOptions>) -> Result<bool, Error> {
                match self {
                    $(Chain::$name => $name::validate_address(address, option),)*
                }
            }
        }
    }
}

createChains!(NONE, KLV, TRX, BTC, ETH, MATIC, DOT);

// pub enum Chain {
//     NONE, // 0
//     TRX,
//     BTC,
//     ETH,
//     XRP,
//     LTC, // 5
//     XLM,
//     COSMOS,
//     EOS,
//     ONT,
//     KLAY, // 10
//     DASH,
//     DOGE,
//     IOTX,
//     ONE,
//     SYS, // 15
//     DGB,
//     BNB,
//     BCH,
//     VET,
//     ADA, // 20
//     DOT,
//     XMR,
//     XTZ,
//     EGLD,
//     NEO, // 25
//     BSC,
//     KSM,
//     MATIC,
//     REEF,
//     HT, // 30
//     ICP,
//     MOVR,
//     TKLV, // 33
//     GLMR,
//     SDN, // 35
//     ASTR,
//     SYSNEVM,
//     KLV,
//     AVAX,
//     SOL, // 40
//     KAR,
//     AIR,
//     FLOW,
//     KILT,
//     CUDOS, //45
//     ACA,
//     CFG,
//     TIA,
//     AURA,
//     APT, //50
// }

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseChain {
    #[wasm_bindgen(skip)]
    pub name: &'static str,
    #[wasm_bindgen(skip)]
    pub symbol: &'static str,
    #[wasm_bindgen(skip)]
    pub precision: u8,
    #[wasm_bindgen(skip)]
    pub chain_code: u8,
}

#[wasm_bindgen]
impl BaseChain {
    #[wasm_bindgen(js_name = getName)]
    pub fn get_name(&self) -> String {
        self.name.to_string()
    }

    #[wasm_bindgen(js_name = getSymbol)]
    pub fn get_symbol(&self) -> String {
        self.symbol.to_string()
    }

    #[wasm_bindgen(js_name = getPrecision)]
    pub fn get_precision(&self) -> u8 {
        self.precision
    }

    #[wasm_bindgen(js_name = getChainCode)]
    pub fn get_chain_code(&self) -> u8 {
        self.chain_code
    }
}
