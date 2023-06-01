use crate::error::Error;
use crate::Bytes32;

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Hash {
    data: Bytes32,
}

#[wasm_bindgen]
impl Hash {
    #[wasm_bindgen(constructor)]
    pub fn new(data: &str) -> Result<Hash, Error> {
        log::debug!("Hash::new({})", data);

        let value = Bytes32::from_str(data).map_err(|e| Error::InvalidString(e.to_string()))?;

        Ok(Self { data: value })
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.data.to_string()
    }

    #[wasm_bindgen(js_name = bytes)]
    pub fn bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    #[wasm_bindgen(js_name = fromSlice)]
    pub fn from_slice(data: &[u8]) -> Result<Hash, Error> {
        // check length
        if data.len() != Bytes32::LEN {
            return Err(Error::InvalidLen(format!(
                "expected {}, found {}",
                Bytes32::LEN,
                data.len()
            )));
        }
        let value = unsafe { Bytes32::from_slice_unchecked(data) };

        Ok(Self { data: value })
    }

    #[wasm_bindgen(js_name = fromVec)]
    pub fn from_vec(data: Vec<u8>) -> Result<Hash, Error> {
        Hash::from_slice(data.as_slice())
    }
}

impl From<Bytes32> for Hash {
    fn from(data: Bytes32) -> Self {
        Self { data }
    }
}

impl From<Hash> for Bytes32 {
    fn from(hash: Hash) -> Self {
        hash.data
    }
}
