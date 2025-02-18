use crate::KOSError;
use num_bigint::BigInt;
use num_traits::{One, Pow, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Default, Serialize, Deserialize, uniffi::Record)]
pub struct BigNumber {
    pub value: String,
}

impl BigNumber {
    pub fn new(value: &str) -> Result<Self, KOSError> {
        BigInt::from_str(value)
            .map(|_| BigNumber {
                value: value.to_string(),
            })
            .map_err(|_| KOSError::KOSNumber("Invalid number".to_string()))
    }

    pub fn to_bigint(&self) -> Result<BigInt, KOSError> {
        BigInt::from_str(&self.value).map_err(|_| KOSError::KOSNumber("Invalid number".to_string()))
    }
}

#[uniffi::export]
fn big_number_new(value: String) -> Result<BigNumber, KOSError> {
    BigNumber::new(&value)
}

#[uniffi::export]
fn big_number_add(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left + right).to_string(),
    })
}

#[uniffi::export]
fn big_number_subtract(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left - right).to_string(),
    })
}

#[uniffi::export]
fn big_number_multiply(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(BigNumber {
        value: (left * right).to_string(),
    })
}

#[uniffi::export]
fn big_number_divide(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    if right.is_zero() {
        return Err(KOSError::KOSNumber("Division by zero".to_string()));
    }
    Ok(BigNumber {
        value: (left / right).to_string(),
    })
}

#[uniffi::export]
fn big_number_is_equal(lhs: BigNumber, rhs: BigNumber) -> Result<bool, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(left == right)
}

#[uniffi::export]
fn big_number_is_gt(lhs: BigNumber, rhs: BigNumber) -> Result<bool, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(left > right)
}

#[uniffi::export]
fn big_number_is_gte(lhs: BigNumber, rhs: BigNumber) -> Result<bool, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(left >= right)
}

#[uniffi::export]
fn big_number_is_lt(lhs: BigNumber, rhs: BigNumber) -> Result<bool, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(left < right)
}

#[uniffi::export]
fn big_number_is_lte(lhs: BigNumber, rhs: BigNumber) -> Result<bool, KOSError> {
    let left = lhs.to_bigint()?;
    let right = rhs.to_bigint()?;
    Ok(left <= right)
}

#[uniffi::export]
fn big_number_pow(base: BigNumber, exponent: BigNumber) -> Result<BigNumber, KOSError> {
    let base_int = base.to_bigint()?;
    let exp_int = exponent.to_bigint()?;

    if exp_int.is_negative() {
        return Err(KOSError::KOSNumber(
            "Exponent must be non-negative".to_string(),
        ));
    }

    let exp_u32 = match exp_int.to_u32() {
        Some(e) => e,
        None => return Err(KOSError::KOSNumber("Exponent too large".to_string())),
    };

    Ok(BigNumber {
        value: base_int.pow(exp_u32).to_string(),
    })
}

#[uniffi::export]
fn big_number_absolute(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val = value.to_bigint()?;
    Ok(BigNumber {
        value: val.abs().to_string(),
    })
}

#[uniffi::export]
fn big_number_is_zero(value: BigNumber) -> Result<bool, KOSError> {
    Ok(value.to_bigint()?.is_zero())
}

#[uniffi::export]
fn big_number_increment(value: BigNumber) -> Result<BigNumber, KOSError> {
    let current = value.to_bigint()?;
    Ok(BigNumber {
        value: (current + BigInt::one()).to_string(),
    })
}

#[uniffi::export]
fn big_number_decrement(value: BigNumber) -> Result<BigNumber, KOSError> {
    let current = value.to_bigint()?;
    Ok(BigNumber {
        value: (current - BigInt::one()).to_string(),
    })
}

#[uniffi::export]
fn big_number_is_positive(value: BigNumber) -> Result<bool, KOSError> {
    Ok(value.to_bigint()?.is_positive())
}

#[uniffi::export]
fn big_number_is_negative(value: BigNumber) -> Result<bool, KOSError> {
    Ok(value.to_bigint()?.is_negative())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_number_new() {
        assert!(big_number_new("123".to_string()).is_ok());
        assert!(big_number_new("-456".to_string()).is_ok());
        assert!(big_number_new("0".to_string()).is_ok());
        assert!(big_number_new("9999999999999999999999999999".to_string()).is_ok());

        assert!(big_number_new("abc".to_string()).is_err());
        assert!(big_number_new("123.456".to_string()).is_err());
        assert!(big_number_new("".to_string()).is_err());
    }

    #[test]
    fn test_big_number_add() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("456".to_string()).unwrap();
        let result = big_number_add(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "579");

        let large1 = big_number_new("999999999999999999999999999".to_string()).unwrap();
        let large2 = big_number_new("1".to_string()).unwrap();
        let result = big_number_add(large1, large2).unwrap();
        assert_eq!(result.value, "1000000000000000000000000000");

        let neg = big_number_new("-456".to_string()).unwrap();
        let result = big_number_add(a.clone(), neg).unwrap();
        assert_eq!(result.value, "-333");
    }

    #[test]
    fn test_big_number_subtract() {
        let a = big_number_new("456".to_string()).unwrap();
        let b = big_number_new("123".to_string()).unwrap();
        let result = big_number_subtract(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "333");

        let result = big_number_subtract(b.clone(), a.clone()).unwrap();
        assert_eq!(result.value, "-333");

        let large1 = big_number_new("1000000000000000000000000000".to_string()).unwrap();
        let large2 = big_number_new("1".to_string()).unwrap();
        let result = big_number_subtract(large1, large2).unwrap();
        assert_eq!(result.value, "999999999999999999999999999");
    }

    #[test]
    fn test_big_number_multiply() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("456".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "56088");

        let neg = big_number_new("-123".to_string()).unwrap();
        let result = big_number_multiply(neg, b.clone()).unwrap();
        assert_eq!(result.value, "-56088");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), zero).unwrap();
        assert_eq!(result.value, "0");

        let large1 = big_number_new("999999999".to_string()).unwrap();
        let large2 = big_number_new("999999999".to_string()).unwrap();
        let result = big_number_multiply(large1, large2).unwrap();
        assert_eq!(result.value, "999999998000000001");
    }

    #[test]
    fn test_big_number_divide() {
        let a = big_number_new("100".to_string()).unwrap();
        let b = big_number_new("5".to_string()).unwrap();
        let result = big_number_divide(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "20");

        let c = big_number_new("10".to_string()).unwrap();
        let d = big_number_new("3".to_string()).unwrap();
        let result = big_number_divide(c.clone(), d.clone()).unwrap();
        assert_eq!(result.value, "3");

        let zero = big_number_new("0".to_string()).unwrap();
        assert!(big_number_divide(a.clone(), zero).is_err());

        let neg = big_number_new("-100".to_string()).unwrap();
        let result = big_number_divide(neg, b.clone()).unwrap();
        assert_eq!(result.value, "-20");
    }

    #[test]
    fn test_big_number_is_zero() {
        let zero = big_number_new("0".to_string()).unwrap();
        let non_zero = big_number_new("123".to_string()).unwrap();

        assert!(big_number_is_zero(zero).unwrap());
        assert!(!big_number_is_zero(non_zero).unwrap());
    }

    #[test]
    fn test_big_number_increment_decrement() {
        let a = big_number_new("123".to_string()).unwrap();
        let result = big_number_increment(a.clone()).unwrap();
        assert_eq!(result.value, "124");

        let b = big_number_new("123".to_string()).unwrap();
        let result = big_number_decrement(b.clone()).unwrap();
        assert_eq!(result.value, "122");

        let large = big_number_new("999999999999999999999999999".to_string()).unwrap();
        let result = big_number_increment(large.clone()).unwrap();
        assert_eq!(result.value, "1000000000000000000000000000");

        let result = big_number_decrement(result).unwrap();
        assert_eq!(result.value, "999999999999999999999999999");
    }

    #[test]
    fn test_big_number_is_positive_negative() {
        let pos = big_number_new("123".to_string()).unwrap();
        assert!(big_number_is_positive(pos.clone()).unwrap());
        assert!(!big_number_is_negative(pos.clone()).unwrap());

        let neg = big_number_new("-456".to_string()).unwrap();
        assert!(!big_number_is_positive(neg.clone()).unwrap());
        assert!(big_number_is_negative(neg.clone()).unwrap());

        let zero = big_number_new("0".to_string()).unwrap();
        assert!(!big_number_is_positive(zero.clone()).unwrap());
        assert!(!big_number_is_negative(zero.clone()).unwrap());
    }

    #[test]
    fn test_big_number_is_equal() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("123".to_string()).unwrap();
        let c = big_number_new("456".to_string()).unwrap();

        assert!(big_number_is_equal(a.clone(), b.clone()).unwrap());
        assert!(!big_number_is_equal(a.clone(), c.clone()).unwrap());

        let large1 = big_number_new("999999999999999999999999999".to_string()).unwrap();
        let large2 = big_number_new("999999999999999999999999999".to_string()).unwrap();
        assert!(big_number_is_equal(large1, large2).unwrap());
    }

    #[test]
    fn test_big_number_comparison() {
        let a = big_number_new("100".to_string()).unwrap();
        let b = big_number_new("200".to_string()).unwrap();
        let equal_to_a = big_number_new("100".to_string()).unwrap();

        assert!(big_number_is_gt(b.clone(), a.clone()).unwrap());
        assert!(!big_number_is_gt(a.clone(), b.clone()).unwrap());
        assert!(!big_number_is_gt(a.clone(), equal_to_a.clone()).unwrap());

        assert!(big_number_is_gte(b.clone(), a.clone()).unwrap());
        assert!(!big_number_is_gte(a.clone(), b.clone()).unwrap());
        assert!(big_number_is_gte(a.clone(), equal_to_a.clone()).unwrap());

        assert!(big_number_is_lt(a.clone(), b.clone()).unwrap());
        assert!(!big_number_is_lt(b.clone(), a.clone()).unwrap());
        assert!(!big_number_is_lt(a.clone(), equal_to_a.clone()).unwrap());

        assert!(big_number_is_lte(a.clone(), b.clone()).unwrap());
        assert!(!big_number_is_lte(b.clone(), a.clone()).unwrap());
        assert!(big_number_is_lte(a.clone(), equal_to_a.clone()).unwrap());

        let neg = big_number_new("-100".to_string()).unwrap();
        assert!(big_number_is_gt(a.clone(), neg.clone()).unwrap());
        assert!(big_number_is_lt(neg.clone(), a.clone()).unwrap());
    }

    #[test]
    fn test_big_number_pow() {
        let base = big_number_new("2".to_string()).unwrap();
        let exp = big_number_new("3".to_string()).unwrap();
        let result = big_number_pow(base.clone(), exp.clone()).unwrap();
        assert_eq!(result.value, "8");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_pow(base.clone(), zero.clone()).unwrap();
        assert_eq!(result.value, "1");

        let ten = big_number_new("10".to_string()).unwrap();
        let exp10 = big_number_new("10".to_string()).unwrap();
        let result = big_number_pow(ten.clone(), exp10.clone()).unwrap();
        assert_eq!(result.value, "10000000000");

        let neg_exp = big_number_new("-1".to_string()).unwrap();
        assert!(big_number_pow(base.clone(), neg_exp.clone()).is_err());

        let neg_base = big_number_new("-2".to_string()).unwrap();
        let exp2 = big_number_new("2".to_string()).unwrap();
        let result = big_number_pow(neg_base.clone(), exp2.clone()).unwrap();
        assert_eq!(result.value, "4");

        let exp3 = big_number_new("3".to_string()).unwrap();
        let result = big_number_pow(neg_base.clone(), exp3.clone()).unwrap();
        assert_eq!(result.value, "-8");
    }

    #[test]
    fn test_big_number_absolute() {
        let positive = big_number_new("123".to_string()).unwrap();
        let result = big_number_absolute(positive.clone()).unwrap();
        assert_eq!(result.value, "123");

        let negative = big_number_new("-456".to_string()).unwrap();
        let result = big_number_absolute(negative.clone()).unwrap();
        assert_eq!(result.value, "456");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_absolute(zero.clone()).unwrap();
        assert_eq!(result.value, "0");

        let large_neg = big_number_new("-999999999999999999999999999".to_string()).unwrap();
        let result = big_number_absolute(large_neg).unwrap();
        assert_eq!(result.value, "999999999999999999999999999");
    }
}
