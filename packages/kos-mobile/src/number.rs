use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Default, Serialize, Deserialize, uniffi::Record)]
pub struct BigNumber {
    pub value: String,
}

impl BigNumber {
    pub fn new(value: &str) -> Result<Self, String> {
        BigInt::from_str(value)
            .map(|_| BigNumber {
                value: value.to_string(),
            })
            .map_err(|_| format!("Invalid number format: {}", value))
    }

    pub fn to_bigint(&self) -> Result<BigInt, String> {
        BigInt::from_str(&self.value).map_err(|_| format!("Failed to parse BigInt: {}", self.value))
    }
}

#[uniffi::export]
fn big_number_new(value: String) -> Result<BigNumber, String> {
    BigNumber::new(&value)
}

#[uniffi::export]
fn big_number_add(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, String> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left + right).to_string(),
    })
}

#[uniffi::export]
fn big_number_subtract(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, String> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left - right).to_string(),
    })
}

#[uniffi::export]
fn big_number_multiply(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, String> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left * right).to_string(),
    })
}

#[uniffi::export]
fn big_number_divide(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, String> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    if right.is_zero() {
        return Err("Cannot divide by zero".to_string());
    }
    Ok(BigNumber {
        value: (left / right).to_string(),
    })
}

#[uniffi::export]
fn big_number_is_zero(value: BigNumber) -> Result<bool, String> {
    Ok(value.to_bigint()?.is_zero())
}

#[uniffi::export]
fn big_number_increment(value: BigNumber) -> Result<BigNumber, String> {
    let current = value.to_bigint()?;
    Ok(BigNumber {
        value: (current + BigInt::one()).to_string(),
    })
}

#[uniffi::export]
fn big_number_decrement(value: BigNumber) -> Result<BigNumber, String> {
    let current = value.to_bigint()?;
    Ok(BigNumber {
        value: (current - BigInt::one()).to_string(),
    })
}

#[uniffi::export]
fn big_number_is_positive(value: BigNumber) -> Result<bool, String> {
    Ok(value.to_bigint()?.is_positive())
}

#[uniffi::export]
fn big_number_is_negative(value: BigNumber) -> Result<bool, String> {
    Ok(value.to_bigint()?.is_negative())
}
