use crate::error::Error;

use core::cmp::Ordering;
use std::{ops::Deref, str::FromStr};

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize, Serializer};

use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
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

impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.v.to_string())
    }
}

impl<'de> Deserialize<'de> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
            .map(|v| BigNumber { v })
    }
}

impl Default for BigNumber {
    fn default() -> Self {
        Self {
            v: BigInt::default(),
        }
    }
}

impl FromStr for BigNumber {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BigNumber::from_string(s)
    }
}

impl TryInto<BigNumber> for &str {
    type Error = Error;

    fn try_into(self) -> Result<BigNumber, Self::Error> {
        BigNumber::from_str(self)
    }
}

impl TryFrom<String> for BigNumber {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        BigNumber::from_str(&s)
    }
}

#[wasm_bindgen]
impl BigNumber {
    #[wasm_bindgen(js_name = "fromString")]
    pub fn from_string(value: &str) -> Result<BigNumber, Error> {
        let value = value.trim().replace("_", "");

        Ok(BigNumber {
            v: BigInt::from_str(value.as_str())
                .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
        })
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.v.to_string()
    }

    #[wasm_bindgen(js_name = "toHex")]
    pub fn to_hex(&self) -> String {
        format!("{:#x}", self.v)
    }

    #[wasm_bindgen(js_name = "toNumber")]
    pub fn to_number(&self) -> f64 {
        self.v.to_f64().unwrap_or(0.0)
    }

    #[wasm_bindgen(js_name = "toI64")]
    pub fn to_i64(&self) -> i64 {
        self.v.to_i64().unwrap_or(0)
    }

    #[wasm_bindgen(js_name = "toU64")]
    pub fn to_u64(&self) -> u64 {
        self.v.to_u64().unwrap_or(0)
    }

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

    pub fn is_zero(&self) -> bool {
        self.v.is_zero()
    }

    pub fn self_add(mut self, other: &BigNumber) -> Self {
        self.v += &other.v;
        self
    }

    pub fn self_sub(mut self, other: &BigNumber) -> Self {
        self.v -= &other.v;
        self
    }

    pub fn self_mul(mut self, other: &BigNumber) -> Self {
        self.v *= &other.v;
        self
    }

    pub fn self_div(mut self, other: &BigNumber) -> Self {
        self.v /= &other.v;
        self
    }

    pub fn add(self, other: &BigNumber) -> Self {
        BigNumber {
            v: self.v + &other.v,
        }
    }

    pub fn sub(self, other: &BigNumber) -> Self {
        BigNumber {
            v: self.v - &other.v,
        }
    }

    pub fn mul(self, other: &BigNumber) -> Self {
        BigNumber {
            v: self.v * &other.v,
        }
    }

    pub fn div(self, other: &BigNumber) -> Self {
        BigNumber {
            v: self.v / &other.v,
        }
    }

    pub fn gt(&self, other: &BigNumber) -> bool {
        self.v > other.v
    }

    pub fn gte(&self, other: &BigNumber) -> bool {
        self.v >= other.v
    }

    pub fn lt(&self, other: &BigNumber) -> bool {
        self.v < other.v
    }

    pub fn lte(&self, other: &BigNumber) -> bool {
        self.v <= other.v
    }
}

impl PartialEq for BigNumber {
    #[inline]
    fn eq(&self, other: &BigNumber) -> bool {
        self.v.eq(&other.v)
    }
}

impl Eq for BigNumber {}

impl PartialOrd for BigNumber {
    #[inline]
    fn partial_cmp(&self, other: &BigNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigNumber {
    #[inline]
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.v.cmp(&other.v)
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
