use crate::{default::NONE, tron::TRX};

use kos_crypto::{public::PublicKey, secret::SecretKey};
use kos_types::error::Error;
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};
use wasm_bindgen::prelude::*;

macro_rules! createChains {
    ($($name:ident),*) => {
        #[wasm_bindgen]
        #[derive(Serialize, Deserialize, Debug, Copy, Clone, EnumCount, IntoStaticStr)]
        pub enum Chain {
            $($name,)*
        }

        impl Chain {
            pub fn get_address_from_private_key(&self, privatekey: SecretKey) -> Result<String, Error> {
                match self {
                    $(Chain::$name => $name::get_address_from_private_key(privatekey),)*
                }
            }

            pub fn get_address_from_public_key(&self, publickey: PublicKey) -> Result<String, Error> {
                match self {
                    $(Chain::$name => $name::get_address_from_public_key(publickey),)*
                }
            }
        }
    }
}

createChains!(NONE, TRX);

#[wasm_bindgen]
pub fn get_address_from_private_key(
    chain: Chain,
    privatekey: SecretKey,
) -> Result<String, JsError> {
    Ok(chain.get_address_from_private_key(privatekey)?)
}

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
