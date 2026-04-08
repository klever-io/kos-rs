use crate::error::KOSError;
use bigdecimal::BigDecimal;
use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BigNumber {
    #[wasm_bindgen(skip)]
    pub digits: Vec<u32>,
    #[wasm_bindgen(skip)]
    pub scale: i64,
    #[wasm_bindgen(skip)]
    pub sign: Sign,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sign {
    Minus,
    NoSign,
    Plus,
}

impl BigNumber {
    pub fn new(value: &str) -> Result<Self, KOSError> {
        if value.is_empty() {
            return Err(KOSError::kos_number("Invalid number".to_string()));
        }

        // Parse the value to check if it's a valid number
        let parsed_value: BigDecimal = match BigDecimal::from_str(value) {
            Ok(v) => v,
            Err(_) => return Err(KOSError::kos_number("Invalid number format".to_string())),
        };

        let big_number: BigNumber = BigNumber::from_bigdecimal(parsed_value);

        Ok(big_number)
    }

    pub fn from_bigdecimal(value: BigDecimal) -> Self {
        let (decimal_as_bigint, scale) = value.clone().into_bigint_and_scale();

        BigNumber {
            scale,
            sign: sign_from_bigint(value.sign()),
            digits: decimal_as_bigint.to_u32_digits().1,
        }
    }

    pub fn to_bigdecimal(&self) -> BigDecimal {
        BigDecimal::new(
            BigInt::new(sign_to_bigint(self.sign.clone()), self.digits.clone()),
            self.scale,
        )
    }
}

fn sign_from_bigint(sign: num_bigint::Sign) -> Sign {
    match sign {
        num_bigint::Sign::Minus => Sign::Minus,
        num_bigint::Sign::NoSign => Sign::NoSign,
        num_bigint::Sign::Plus => Sign::Plus,
    }
}

fn sign_to_bigint(sign: Sign) -> num_bigint::Sign {
    match sign {
        Sign::Minus => num_bigint::Sign::Minus,
        Sign::NoSign => num_bigint::Sign::NoSign,
        Sign::Plus => num_bigint::Sign::Plus,
    }
}

#[wasm_bindgen(js_name = "bigNumberNew")]
pub fn big_number_new(value: String) -> Result<BigNumber, KOSError> {
    BigNumber::new(&value)
}

#[wasm_bindgen(js_name = "bigNumberNewZero")]
pub fn big_number_new_zero() -> BigNumber {
    BigNumber {
        digits: vec![0],
        scale: 0,
        sign: Sign::NoSign,
    }
}

#[wasm_bindgen(js_name = "bigNumberString")]
pub fn big_number_string(value: BigNumber) -> String {
    value
        .to_bigdecimal()
        .with_scale(32)
        .normalized()
        .to_plain_string()
}

#[wasm_bindgen(js_name = "bigNumberAdd")]
pub fn big_number_add(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left + right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberSubtract")]
pub fn big_number_subtract(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left - right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberMultiply")]
pub fn big_number_multiply(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left * right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberDivide")]
pub fn big_number_divide(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left / right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberPow")]
pub fn big_number_pow(base: BigNumber, exponent: BigNumber) -> Result<BigNumber, KOSError> {
    let exp: BigDecimal = exponent.to_bigdecimal();
    if exp.is_negative() {
        return Err(KOSError::kos_number(
            "Exponent must be non-negative".to_string(),
        ));
    }

    // Convert to u32 for use with the Pow trait
    let exp_u32: u32 = match exp.to_u32() {
        Some(e) => e,
        None => return Err(KOSError::kos_number("Exponent too large".to_string())),
    };

    let base_rat: BigDecimal = base.to_bigdecimal();

    if base_rat.is_zero() || base_rat.is_one() {
        Ok(base)
    } else {
        let mut result: BigInt = BigInt::one();
        let (decimal_as_bigint, scale) = base.clone().to_bigdecimal().into_bigint_and_scale();
        for _ in 0..exp_u32 {
            result *= &decimal_as_bigint;
        }

        Ok(BigNumber::from_bigdecimal(BigDecimal::new(
            result,
            scale * exp_u32 as i64,
        )))
    }
}

#[wasm_bindgen(js_name = "bigNumberIsEqual")]
pub fn big_number_is_equal(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() == rhs.to_bigdecimal()
}

#[wasm_bindgen(js_name = "bigNumberIsGt")]
pub fn big_number_is_gt(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() > rhs.to_bigdecimal()
}

#[wasm_bindgen(js_name = "bigNumberIsGte")]
pub fn big_number_is_gte(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() >= rhs.to_bigdecimal()
}

#[wasm_bindgen(js_name = "bigNumberIsLt")]
pub fn big_number_is_lt(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() < rhs.to_bigdecimal()
}

#[wasm_bindgen(js_name = "bigNumberIsLte")]
pub fn big_number_is_lte(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() <= rhs.to_bigdecimal()
}

#[wasm_bindgen(js_name = "bigNumberAbsolute")]
pub fn big_number_absolute(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();

    Ok(BigNumber::from_bigdecimal(val.abs()))
}

#[wasm_bindgen(js_name = "bigNumberIsZero")]
pub fn big_number_is_zero(value: BigNumber) -> bool {
    value.to_bigdecimal().is_zero()
}

#[wasm_bindgen(js_name = "bigNumberIncrement")]
pub fn big_number_increment(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();
    let result: BigDecimal = val + BigDecimal::one();

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberDecrement")]
pub fn big_number_decrement(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();
    let result: BigDecimal = val - BigDecimal::one();

    Ok(BigNumber::from_bigdecimal(result))
}

#[wasm_bindgen(js_name = "bigNumberIsPositive")]
pub fn big_number_is_positive(value: BigNumber) -> bool {
    let val: BigDecimal = value.to_bigdecimal();
    val.is_positive()
}

#[wasm_bindgen(js_name = "bigNumberIsNegative")]
pub fn big_number_is_negative(value: BigNumber) -> bool {
    let val: BigDecimal = value.to_bigdecimal();
    val.is_negative()
}
