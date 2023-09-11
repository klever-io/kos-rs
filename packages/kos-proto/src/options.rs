use kos_types::{error::Error, number::BigNumber};
use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::*;

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
#[wasm_bindgen]
pub struct KLVOptions {
    #[wasm_bindgen(skip)]
    pub nonce: Option<u64>,
    #[wasm_bindgen(skip)]
    pub kda: Option<String>,
    #[wasm_bindgen(skip)]
    pub kda_royalties: Option<i64>,
    #[wasm_bindgen(skip)]
    pub kda_fee: Option<String>,
    #[wasm_bindgen(skip)]
    pub memo: Option<Vec<String>>,
}

#[wasm_bindgen]
impl KLVOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = setNonce)]
    pub fn set_nonce(&mut self, nonce: i64) {
        self.nonce = Some(nonce as u64);
    }

    #[wasm_bindgen(js_name = getNonce)]
    pub fn get_nonce(&self) -> u64 {
        self.nonce.unwrap_or_default()
    }

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

    #[wasm_bindgen(js_name = getKDA)]
    pub fn get_kda(&self) -> String {
        self.kda.clone().unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setKDARoyalties)]
    pub fn set_kda_royalties(&mut self, royalties: i64) {
        self.kda_royalties = Some(royalties);
    }

    #[wasm_bindgen(js_name = getKDARoyalties)]
    pub fn get_kda_royalties(&self) -> i64 {
        self.kda_royalties.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setKDAFee)]
    pub fn set_kda_fee(&mut self, fee: &str) {
        self.kda_fee = Some(fee.to_owned());
    }

    #[wasm_bindgen(js_name = getKDAFee)]
    pub fn get_kda_fee(&self) -> String {
        self.kda_fee.clone().unwrap_or_default()
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
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = setToken)]
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_owned());
    }

    #[wasm_bindgen(js_name = getToken)]
    pub fn get_token(&self) -> String {
        self.token.clone().unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setFeeLimit)]
    pub fn set_fee_limit(&mut self, fee_limit: u64) {
        self.fee_limit = Some(fee_limit as i64);
    }

    #[wasm_bindgen(js_name = getFeeLimit)]
    pub fn get_fee_limit(&self) -> u64 {
        self.fee_limit.unwrap_or_default() as u64
    }

    #[wasm_bindgen(js_name = setMemo)]
    pub fn set_memo(&mut self, memo: &str) {
        self.memo = Some(memo.to_owned());
    }

    #[wasm_bindgen(js_name = getMemo)]
    pub fn get_memo(&self) -> String {
        self.memo.clone().unwrap_or_default()
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
    #[wasm_bindgen(skip)]
    pub legacy_type: Option<bool>,
    #[wasm_bindgen(skip)]
    pub nonce: Option<u64>,
    #[wasm_bindgen(skip)]
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
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = setLegacyType)]
    pub fn set_legacy_type(&mut self, legacy_type: bool) {
        self.legacy_type = Some(legacy_type);
    }

    #[wasm_bindgen(js_name = getLegacyType)]
    pub fn get_legacy_type(&self) -> bool {
        self.legacy_type.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setNonce)]
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = Some(nonce);
    }

    #[wasm_bindgen(js_name = getNonce)]
    pub fn get_nonce(&self) -> u64 {
        self.nonce.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setChainId)]
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = Some(chain_id);
    }

    #[wasm_bindgen(js_name = getChainId)]
    pub fn get_chain_id(&self) -> u64 {
        self.chain_id.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setToken)]
    pub fn set_token(&mut self, token: &str) {
        self.token = Some(token.to_owned());
    }

    #[wasm_bindgen(js_name = getToken)]
    pub fn get_token(&self) -> String {
        self.token.clone().unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setGasLimit)]
    pub fn set_gas_limit(&mut self, gas_limit: &str) -> Result<(), Error> {
        self.gas_limit = Some(BigNumber::from_string(gas_limit)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = getGasLimit)]
    pub fn get_gas_limit(&self) -> String {
        self.gas_limit.clone().unwrap_or_default().to_string()
    }

    #[wasm_bindgen(js_name = setGasPrice)]
    pub fn set_gas_price(&mut self, gas_price: &str) -> Result<(), Error> {
        self.gas_price = Some(BigNumber::from_string(gas_price)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = getGasPrice)]
    pub fn get_gas_price(&self) -> String {
        self.gas_price.clone().unwrap_or_default().to_string()
    }

    #[wasm_bindgen(js_name = setContractData)]
    pub fn set_contract_data(&mut self, contract_data: &[u8]) {
        self.contract_data = Some(contract_data.to_owned());
    }

    #[wasm_bindgen(js_name = getContractData)]
    pub fn get_contract_data(&self) -> Vec<u8> {
        self.contract_data.clone().unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setMaxFeePerGas)]
    pub fn set_max_fee_per_gas(&mut self, max_fee_per_gas: &str) -> Result<(), Error> {
        self.max_fee_per_gas = Some(BigNumber::from_string(max_fee_per_gas)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = getMaxFeePerGas)]
    pub fn get_max_fee_per_gas(&self) -> String {
        self.max_fee_per_gas.clone().unwrap_or_default().to_string()
    }

    #[wasm_bindgen(js_name = setMaxPriorityFeePerGas)]
    pub fn set_max_priority_fee_per_gas(
        &mut self,
        max_priority_fee_per_gas: &str,
    ) -> Result<(), Error> {
        self.max_priority_fee_per_gas = Some(BigNumber::from_string(max_priority_fee_per_gas)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = getMaxPriorityFeePerGas)]
    pub fn get_max_priority_fee_per_gas(&self) -> String {
        self.max_priority_fee_per_gas
            .clone()
            .unwrap_or_default()
            .to_string()
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
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = setETHOptions)]
    pub fn set_eth_options(&mut self, options: &ETHOptions) {
        self.eth = options.clone();
    }

    #[wasm_bindgen(js_name = getETHOptions)]
    pub fn get_eth_options(&self) -> ETHOptions {
        self.eth.clone()
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[wasm_bindgen]
pub struct BTCOptions {
    /// hex magic from network (default is bitcoin mainnet)
    #[wasm_bindgen(skip)]
    pub network: Option<String>,
    #[wasm_bindgen(skip)]
    pub sats_per_bytes: Option<u64>,
    #[wasm_bindgen(skip)]
    pub dust_value: Option<BigNumber>,
    #[wasm_bindgen(skip)]
    pub send_all: Option<bool>,
    #[wasm_bindgen(skip)]
    pub change_address: Option<String>,
    #[wasm_bindgen(skip)]
    pub receivers: Option<Vec<(String, BigNumber)>>,
    #[wasm_bindgen(skip)]
    pub rbf: Option<bool>,
}

#[wasm_bindgen]
impl BTCOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = setNetwork)]
    pub fn set_network(&mut self, network: &str) {
        self.network = Some(network.to_owned());
    }

    #[wasm_bindgen(js_name = getNetwork)]
    pub fn get_network(&self) -> String {
        self.network.clone().unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setSatsPerBytes)]
    pub fn set_sats_per_bytes(&mut self, sats_per_bytes: u64) {
        self.sats_per_bytes = Some(sats_per_bytes);
    }

    #[wasm_bindgen(js_name = getSatsPerBytes)]
    pub fn get_sats_per_bytes(&self) -> u64 {
        self.sats_per_bytes.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setDustValue)]
    pub fn set_dust_value(&mut self, dust_value: &str) -> Result<(), Error> {
        self.dust_value = Some(BigNumber::from_string(dust_value)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = getDustValue)]
    pub fn get_dust_value(&self) -> String {
        self.dust_value.clone().unwrap_or_default().to_string()
    }

    #[wasm_bindgen(js_name = setSendAll)]
    pub fn set_send_all(&mut self, send_all: bool) {
        self.send_all = Some(send_all);
    }

    #[wasm_bindgen(js_name = getSendAll)]
    pub fn get_send_all(&self) -> bool {
        self.send_all.unwrap_or_default()
    }

    #[wasm_bindgen(js_name = setChangeAddress)]
    pub fn set_change_address(&mut self, change_address: &str) {
        self.change_address = Some(change_address.to_owned());
    }

    #[wasm_bindgen(js_name = getChangeAddress)]
    pub fn get_change_address(&self) -> String {
        self.change_address.clone().unwrap_or_default()
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

    #[wasm_bindgen(js_name = getReceivers)]
    pub fn get_receivers(&self) -> Vec<JsValue> {
        self.receivers
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(addr, amount)| {
                let obj = serde_json::json!({
                    "address": addr,
                    "amount": amount.to_string(),
                });
                obj.to_string().into()
            })
            .collect()
    }

    #[wasm_bindgen(js_name = setRBF)]
    pub fn set_rbf(&mut self, rbf: bool) {
        self.rbf = Some(rbf);
    }

    #[wasm_bindgen(js_name = getRBF)]
    pub fn get_rbf(&self) -> bool {
        self.rbf.unwrap_or_default()
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
