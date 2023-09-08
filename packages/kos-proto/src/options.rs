use kos_types::{error::Error, number::BigNumber};
use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::*;

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
#[wasm_bindgen]
pub struct KLVOptions {
    pub nonce: Option<u64>,
    #[wasm_bindgen(skip)]
    pub kda: Option<String>,
    #[wasm_bindgen(js_name = kdaRoyalties)]
    pub kda_royalties: Option<i64>,
    #[wasm_bindgen(skip)]
    pub kda_fee: Option<String>,
    #[wasm_bindgen(skip)]
    pub memo: Option<Vec<String>>,
}

#[wasm_bindgen]
impl KLVOptions {
    #[wasm_bindgen(js_name = addMemo)]
    pub fn add_memo(&mut self, data: &str) {
        let mut memo = self.memo.clone().unwrap_or_default();
        memo.push(data.to_owned());

        self.memo = Some(memo);
    }

    #[wasm_bindgen(js_name = getMemo)]
    pub fn get_memo(&self) -> Vec<JsValue> {
        self.memo
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|m| JsValue::from_str(&m))
            .collect()
    }

    #[wasm_bindgen(js_name = setKDA)]
    pub fn set_kda(&mut self, kda: &str) {
        self.kda = Some(kda.to_owned());
    }

    #[wasm_bindgen(js_name = setKDAFee)]
    pub fn set_kda_fee(&mut self, fee: &str) {
        self.kda_fee = Some(fee.to_owned());
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[wasm_bindgen]
pub struct TRXOptions {
    #[wasm_bindgen(skip)]
    pub token: Option<String>,
    #[wasm_bindgen(js_name = feeLimit)]
    pub fee_limit: Option<i64>,
    #[wasm_bindgen(skip)]
    pub memo: Option<String>,
}

#[wasm_bindgen]
impl TRXOptions {
    #[wasm_bindgen(js_name = setToken)]
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_owned());
    }

    #[wasm_bindgen(js_name = setFeeLimit)]
    pub fn set_fee_limit(&mut self, fee_limit: u64) {
        self.fee_limit = Some(fee_limit as i64);
    }

    #[wasm_bindgen(js_name = setMemo)]
    pub fn set_memo(&mut self, memo: &str) {
        self.memo = Some(memo.to_owned());
    }
}

impl Default for TRXOptions {
    fn default() -> Self {
        Self {
            token: None,
            fee_limit: Some(10_000_000),
            memo: None,
        }
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[wasm_bindgen]
pub struct ETHOptions {
    #[wasm_bindgen(js_name = legacyType)]
    pub legacy_type: Option<bool>,
    pub nonce: Option<u64>,
    #[wasm_bindgen(js_name = chainId)]
    pub chain_id: Option<u64>,
    #[wasm_bindgen(skip)]
    pub token: Option<String>,
    #[wasm_bindgen(skip)]
    pub gas_limit: Option<BigNumber>,
    #[wasm_bindgen(skip)]
    pub gas_price: Option<BigNumber>,
    #[wasm_bindgen(skip)]
    pub contract_data: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub max_fee_per_gas: Option<BigNumber>,
    #[wasm_bindgen(skip)]
    pub max_priority_fee_per_gas: Option<BigNumber>,
}

#[wasm_bindgen]
impl ETHOptions {
    #[wasm_bindgen(js_name = setToken)]
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_owned());
    }

    #[wasm_bindgen(js_name = setGasLimit)]
    pub fn set_gas_limit(&mut self, gas_limit: &str) -> Result<(), Error> {
        self.gas_limit = Some(BigNumber::from_string(gas_limit)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = setGasPrice)]
    pub fn set_gas_price(&mut self, gas_price: &str) -> Result<(), Error> {
        self.gas_price = Some(BigNumber::from_string(gas_price)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = setContractData)]
    pub fn set_contract_data(&mut self, contract_data: &[u8]) {
        self.contract_data = Some(contract_data.to_owned());
    }

    #[wasm_bindgen(js_name = setMaxFeePerGas)]
    pub fn set_max_fee_per_gas(&mut self, max_fee_per_gas: &str) -> Result<(), Error> {
        self.max_fee_per_gas = Some(BigNumber::from_string(max_fee_per_gas)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = setMaxPriorityFeePerGas)]
    pub fn set_max_priority_fee_per_gas(
        &mut self,
        max_priority_fee_per_gas: &str,
    ) -> Result<(), Error> {
        self.max_priority_fee_per_gas = Some(BigNumber::from_string(max_priority_fee_per_gas)?);
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[wasm_bindgen]
pub struct MATICOptions {
    #[wasm_bindgen(skip)]
    pub eth: ETHOptions,
}

#[wasm_bindgen]
impl MATICOptions {
    #[wasm_bindgen(js_name = setETHOptions)]
    pub fn set_eth_options(&mut self, options: &ETHOptions) {
        self.eth = options.clone();
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[wasm_bindgen]
pub struct BTCOptions {
    /// hex magic from network (default is bitcoin mainnet)
    #[wasm_bindgen(skip)]
    pub network: Option<String>,
    #[wasm_bindgen(js_name = satsPerBytes)]
    pub sats_per_bytes: Option<u64>,
    #[wasm_bindgen(skip)]
    pub dust_value: Option<BigNumber>,
    #[wasm_bindgen(js_name = sendAll)]
    pub send_all: Option<bool>,
    #[wasm_bindgen(skip)]
    pub change_address: Option<String>,
    #[wasm_bindgen(skip)]
    pub receivers: Option<Vec<(String, BigNumber)>>,
    pub rbf: Option<bool>,
}

#[wasm_bindgen]
impl BTCOptions {
    #[wasm_bindgen(js_name = setNetwork)]
    pub fn set_network(&mut self, network: &str) {
        self.network = Some(network.to_owned());
    }

    #[wasm_bindgen(js_name = setDustValue)]
    pub fn set_dust_value(&mut self, dust_value: &str) -> Result<(), Error> {
        self.dust_value = Some(BigNumber::from_string(dust_value)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = setChangeAddress)]
    pub fn set_change_address(&mut self, change_address: &str) {
        self.change_address = Some(change_address.to_owned());
    }

    #[wasm_bindgen(js_name = addReceiver)]
    pub fn addr_receiver(&mut self, addr: &str, amount: &str) -> Result<(), Error> {
        let amount = BigNumber::from_string(amount)?;
        let receiver = (addr.to_owned(), amount);

        let mut receivers = self.receivers.clone().unwrap_or_default();
        receivers.push(receiver);

        self.receivers = Some(receivers);

        Ok(())
    }
}

impl BTCOptions {
    pub fn dust_value(&self) -> BigNumber {
        self.dust_value.clone().unwrap_or(BigNumber::from(546))
    }
    pub fn sats_per_bytes(&self) -> u64 {
        self.sats_per_bytes.unwrap_or(1)
    }
    pub fn receivers(&self) -> Vec<(String, BigNumber)> {
        self.receivers.clone().unwrap_or_default()
    }

    pub fn rbf(&self) -> bool {
        self.rbf.unwrap_or(false)
    }
}
