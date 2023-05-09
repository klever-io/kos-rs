use core::fmt;
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoStaticStr};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Copy, Clone, EnumCount, IntoStaticStr)]
pub enum Chain {
    NONE, // 0
    TRX,
    BTC,
    ETH,
    XRP,
    LTC, // 5
    XLM,
    COSMOS,
    EOS,
    ONT,
    KLAY, // 10
    DASH,
    DOGE,
    IOTX,
    ONE,
    SYS, // 15
    DGB,
    BNB,
    BCH,
    VET,
    ADA, // 20
    DOT,
    XMR,
    XTZ,
    EGLD,
    NEO, // 25
    BSC,
    KSM,
    MATIC,
    REEF,
    HT, // 30
    ICP,
    MOVR,
    TKLV, // 33
    GLMR,
    SDN, // 35
    ASTR,
    SYSNEVM,
    KLV,
    AVAX,
    SOL, // 40
    KAR,
    AIR,
    FLOW,
    KILT,
    CUDOS, //45
    ACA,
    CFG,
    TIA,
    AURA,
    APT, //50
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
