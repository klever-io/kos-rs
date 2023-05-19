use std::ops::Deref;

use num_bigint::BigInt;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct BigNumber {
    v: BigInt,
}

impl Deref for BigNumber {
    type Target = BigInt;

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

#[wasm_bindgen]
impl BigNumber {
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.v.to_string()
    }

    #[wasm_bindgen(js_name = "toHex")]
    pub fn to_hex(&self) -> String {
        format!("{:#x}", self.v)
    }

    // #[wasm_bindgen(js_name = "toNumber")]
    // pub fn to_number(&self) -> f64 {
    //     self.v.to_f64().unwrap_or(0.0)
    // }

    #[wasm_bindgen(js_name = "withPrecision")]
    pub fn with_precision(&self, precision: u32) -> String {
        let mut s = self.v.to_string();
        let len = s.len();
        if len < precision as usize {
            s.insert_str(0, &"0".repeat(precision as usize - len));
        }
        let len = s.len();
        let index = len - precision as usize;
        s.insert(index, '.');
        s
    }
}

macro_rules! impl_from {
    ($($uint_type: ty),*) => {
        $(
            impl From<$uint_type> for BigNumber {
                fn from(s: $uint_type) -> BigNumber {
                    BigNumber {
                        v: BigInt::from(s),
                    }
                }
            }
        )*
    }
}

impl_from!(u8, u16, u32, u64, u128);
impl_from!(i8, i16, i32, i64, i128);

impl ToString for BigNumber {
    fn to_string(&self) -> String {
        self.v.to_string()
    }
}
