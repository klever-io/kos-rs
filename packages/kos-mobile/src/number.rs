use crate::KOSError;
use bigdecimal::BigDecimal;
use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};
use std::str::FromStr;

#[derive(Debug, Clone, uniffi::Record)]
pub struct BigNumber {
    pub digits: Vec<u32>,
    pub scale: i64,
    pub sign: Sign,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Sign {
    Minus,
    NoSign,
    Plus,
}

impl BigNumber {
    pub fn new(value: &str) -> Result<Self, KOSError> {
        if value.is_empty() {
            return Err(KOSError::KOSNumber("Invalid number".to_string()));
        }

        // Parse the value to check if it's a valid number
        let parsed_value: BigDecimal = match BigDecimal::from_str(value) {
            Ok(v) => v,
            Err(_) => return Err(KOSError::KOSNumber("Invalid number format".to_string())),
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

#[uniffi::export]
fn big_number_new(value: String) -> Result<BigNumber, KOSError> {
    BigNumber::new(&value)
}

#[uniffi::export]
fn big_number_new_zero() -> BigNumber {
    BigNumber {
        digits: vec![0],
        scale: 0,
        sign: Sign::NoSign,
    }
}

#[uniffi::export]
fn big_number_string(value: BigNumber) -> String {
    value
        .to_bigdecimal()
        .with_scale(32)
        .normalized()
        .to_plain_string()
}

#[uniffi::export]
fn big_number_add(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left + right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_subtract(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left - right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_multiply(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left * right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_divide(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    let left: BigDecimal = lhs.to_bigdecimal();
    let right: BigDecimal = rhs.to_bigdecimal();

    let result: BigDecimal = left / right;

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_pow(base: BigNumber, exponent: BigNumber) -> Result<BigNumber, KOSError> {
    let exp: BigDecimal = exponent.to_bigdecimal();
    if exp.is_negative() {
        return Err(KOSError::KOSNumber(
            "Exponent must be non-negative".to_string(),
        ));
    }

    // Convert to u32 for use with the Pow trait
    let exp_u32: u32 = match exp.to_u32() {
        Some(e) => e,
        None => return Err(KOSError::KOSNumber("Exponent too large".to_string())),
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

#[uniffi::export]
fn big_number_is_equal(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() == rhs.to_bigdecimal()
}

#[uniffi::export]
fn big_number_is_gt(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() > rhs.to_bigdecimal()
}

#[uniffi::export]
fn big_number_is_gte(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() >= rhs.to_bigdecimal()
}

#[uniffi::export]
fn big_number_is_lt(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() < rhs.to_bigdecimal()
}

#[uniffi::export]
fn big_number_is_lte(lhs: BigNumber, rhs: BigNumber) -> bool {
    lhs.to_bigdecimal() <= rhs.to_bigdecimal()
}

#[uniffi::export]
fn big_number_absolute(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();

    Ok(BigNumber::from_bigdecimal(val.abs()))
}

#[uniffi::export]
fn big_number_is_zero(value: BigNumber) -> bool {
    value.to_bigdecimal().is_zero()
}

#[uniffi::export]
fn big_number_increment(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();
    let result: BigDecimal = val + BigDecimal::one();

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_decrement(value: BigNumber) -> Result<BigNumber, KOSError> {
    let val: BigDecimal = value.to_bigdecimal();
    let result: BigDecimal = val - BigDecimal::one();

    Ok(BigNumber::from_bigdecimal(result))
}

#[uniffi::export]
fn big_number_is_positive(value: BigNumber) -> bool {
    let val: BigDecimal = value.to_bigdecimal();
    val.is_positive()
}

#[uniffi::export]
fn big_number_is_negative(value: BigNumber) -> bool {
    let val: BigDecimal = value.to_bigdecimal();
    val.is_negative()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_number_new() {
        assert!(big_number_new("123".to_string()).is_ok());
        assert!(big_number_new("-456".to_string()).is_ok());
        assert!(big_number_new("0".to_string()).is_ok());

        assert!(big_number_new("123.456".to_string()).is_ok());
        assert!(big_number_new("-789.012".to_string()).is_ok());
        assert!(big_number_new("0.0".to_string()).is_ok());

        assert!(big_number_new("abc".to_string()).is_err());
        assert!(big_number_new("123a".to_string()).is_err());
        assert!(big_number_new("".to_string()).is_err());
    }

    #[test]
    fn test_big_number_add() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("456".to_string()).unwrap();
        let result = big_number_add(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "579");

        let c = big_number_new("-123".to_string()).unwrap();
        let result = big_number_add(b.clone(), c.clone()).unwrap();
        assert_eq!(big_number_string(result), "333");

        let d = big_number_new("123.5".to_string()).unwrap();
        let e = big_number_new("456.7".to_string()).unwrap();

        let result = big_number_add(d.clone(), e.clone()).unwrap();
        assert_eq!(big_number_string(result), "580.2");

        let result = big_number_add(a.clone(), d.clone()).unwrap();
        assert_eq!(big_number_string(result), "246.5");

        let f = big_number_new("123.456".to_string()).unwrap();
        let g = big_number_new("1e5".to_string()).unwrap();
        let result = big_number_add(f.clone(), g.clone()).unwrap();
        assert_eq!(big_number_string(result), "100123.456");
    }

    #[test]
    fn test_big_number_subtract() {
        let a = big_number_new("456".to_string()).unwrap();
        let b = big_number_new("123".to_string()).unwrap();
        let result = big_number_subtract(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "333");

        let result = big_number_subtract(b.clone(), a.clone()).unwrap();
        assert_eq!(big_number_string(result), "-333");

        let c = big_number_new("456.7".to_string()).unwrap();
        let d = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_subtract(c.clone(), d.clone()).unwrap();
        assert_eq!(big_number_string(result), "333.2");

        let result = big_number_subtract(c.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "333.7");

        let a = big_number_new("1000000000.0000000000000000001".to_string()).unwrap();
        let b = big_number_new("1000000000.0000000000000000001".to_string()).unwrap();
        let result = big_number_subtract(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "0");

        let a = big_number_new("1000000000000000.000000000000000000011".to_string()).unwrap();
        let b = big_number_new("1000000000000000.000000000000000000001".to_string()).unwrap();
        let result = big_number_subtract(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "0.00000000000000000001");
    }

    #[test]
    fn test_big_number_multiply() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("456".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "56088");

        let c = big_number_new("-123".to_string()).unwrap();
        let result = big_number_multiply(c.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "-56088");

        let d = big_number_new("12.3".to_string()).unwrap();
        let e = big_number_new("4.56".to_string()).unwrap();
        let result = big_number_multiply(d.clone(), e.clone()).unwrap();
        assert_eq!(big_number_string(result), "56.088");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), zero.clone()).unwrap();
        assert_eq!(big_number_string(result), "0");

        let v1 = big_number_new("1000000000.0000000000000000001".to_string()).unwrap();
        let v2 = big_number_new("1000000000.0000000000000000001".to_string()).unwrap();
        let result2 = big_number_multiply(v1.clone(), v2.clone()).unwrap();
        assert_eq!(big_number_string(result2), "1000000000000000000.0000000002");

        let v1 = big_number_new("1000000000000000.000000000000000000001".to_string()).unwrap();
        let v2 = big_number_new("1000000000000000.000000000000000000001".to_string()).unwrap();
        let result2 = big_number_multiply(v1.clone(), v2.clone()).unwrap();
        assert_eq!(
            big_number_string(result2),
            "1000000000000000000000000000000.000002"
        );

        let v1 = big_number_new("68562856798576893673962586728956729056872".to_string()).unwrap();
        let v2 =
            big_number_new("4534534534534534534.4456456454772389472398573467326893".to_string())
                .unwrap();
        let result2 = big_number_multiply(v1.clone(), v2.clone()).unwrap();
        assert_eq!(big_number_string(result2), "310900641939492821158120256443368825392404212910534543770521.84848435835467083499652468120586");
    }

    #[test]
    fn test_big_number_divide() {
        let a = big_number_new("100".to_string()).unwrap();
        let b = big_number_new("5".to_string()).unwrap();
        let result = big_number_divide(a.clone(), b.clone()).unwrap();
        assert_eq!(big_number_string(result), "20");

        let c = big_number_new("10".to_string()).unwrap();
        let d = big_number_new("3".to_string()).unwrap();
        let result = big_number_divide(c.clone(), d.clone()).unwrap();
        assert_eq!(
            big_number_string(result),
            "3.33333333333333333333333333333333"
        );

        let e = big_number_new("12.6".to_string()).unwrap();
        let f = big_number_new("2.1".to_string()).unwrap();
        let result = big_number_divide(e.clone(), f.clone()).unwrap();
        assert_eq!(big_number_string(result), "6");

        let v1 = big_number_new("68562856798576893673962586728956729056872".to_string()).unwrap();
        let v2 =
            big_number_new("4534534534534534534.4456456454772389472398573467326893".to_string())
                .unwrap();
        let result2 = big_number_divide(v1.clone(), v2.clone()).unwrap();
        assert_eq!(
            big_number_string(result2),
            "15120153188030533505878.87279202398950239411974388454771"
        );

        let a1 = big_number_new(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                .to_string(),
        )
        .unwrap();
        let b2 = big_number_new("2".to_string()).unwrap();
        let result21 = big_number_divide(a1.clone(), b2.clone()).unwrap();
        assert_eq!(
            big_number_string(result21),
            "57896044618658097711785492504343953926634992332820282019728792003956564819967.5"
        );
    }

    #[test]
    fn test_big_number_is_zero() {
        let zero = big_number_new("0".to_string()).unwrap();
        let zero_decimal = big_number_new("0.0".to_string()).unwrap();
        let non_zero = big_number_new("123".to_string()).unwrap();

        assert!(big_number_is_zero(zero));
        assert!(big_number_is_zero(zero_decimal));
        assert!(!big_number_is_zero(non_zero));
    }

    #[test]
    fn test_big_number_increment_decrement() {
        let a = big_number_new("123".to_string()).unwrap();
        let result = big_number_increment(a.clone()).unwrap();
        assert_eq!(big_number_string(result), "124");

        let b = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_increment(b.clone()).unwrap();
        assert_eq!(big_number_string(result), "124.5");

        let c = big_number_new("123".to_string()).unwrap();
        let result = big_number_decrement(c.clone()).unwrap();
        assert_eq!(big_number_string(result), "122");

        let d = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_decrement(d.clone()).unwrap();
        assert_eq!(big_number_string(result), "122.5");
    }

    #[test]
    fn test_big_number_is_positive_negative() {
        let a = big_number_new("123".to_string()).unwrap();
        assert!(big_number_is_positive(a.clone()));
        assert!(!big_number_is_negative(a.clone()));

        let b = big_number_new("-456".to_string()).unwrap();
        assert!(!big_number_is_positive(b.clone()));
        assert!(big_number_is_negative(b.clone()));

        let c = big_number_new("0".to_string()).unwrap();
        assert!(!big_number_is_positive(c.clone()));
        assert!(!big_number_is_negative(c.clone()));
    }

    #[test]
    fn test_big_number_is_equal() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("123".to_string()).unwrap();
        assert!(big_number_is_equal(a.clone(), b.clone()));

        let c = big_number_new("456".to_string()).unwrap();
        assert!(!big_number_is_equal(a.clone(), c.clone()));

        let d = big_number_new("123.0".to_string()).unwrap();
        assert!(big_number_is_equal(a.clone(), d.clone()));

        let e = big_number_new("123.000".to_string()).unwrap();
        assert!(big_number_is_equal(a.clone(), e.clone()));
    }

    #[test]
    fn test_big_number_comparison() {
        let a = big_number_new("100".to_string()).unwrap();
        let b = big_number_new("200".to_string()).unwrap();
        let c = big_number_new("100.0".to_string()).unwrap();
        let d = big_number_new("100.5".to_string()).unwrap();

        assert!(big_number_is_gt(b.clone(), a.clone()));
        assert!(!big_number_is_gt(a.clone(), b.clone()));
        assert!(!big_number_is_gt(a.clone(), c.clone()));
        assert!(big_number_is_gt(d.clone(), a.clone()));

        assert!(big_number_is_gte(b.clone(), a.clone()));
        assert!(big_number_is_gte(a.clone(), c.clone()));
        assert!(!big_number_is_gte(a.clone(), b.clone()));
        assert!(big_number_is_gte(d.clone(), c.clone()));

        assert!(big_number_is_lt(a.clone(), b.clone()));
        assert!(!big_number_is_lt(b.clone(), a.clone()));
        assert!(!big_number_is_lt(c.clone(), a.clone()));
        assert!(big_number_is_lt(c.clone(), d.clone()));

        assert!(big_number_is_lte(a.clone(), b.clone()));
        assert!(big_number_is_lte(c.clone(), a.clone()));
        assert!(!big_number_is_lte(b.clone(), a.clone()));
        assert!(big_number_is_lte(a.clone(), c.clone()));
    }

    #[test]
    fn test_big_number_pow() {
        let base = big_number_new("2".to_string()).unwrap();
        let exp = big_number_new("3".to_string()).unwrap();
        let result = big_number_pow(base.clone(), exp.clone()).unwrap();
        assert_eq!(big_number_string(result), "8");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_pow(base.clone(), zero.clone()).unwrap();
        assert_eq!(big_number_string(result), "1");

        let ten = big_number_new("10".to_string()).unwrap();
        let exp10 = big_number_new("10".to_string()).unwrap();
        let result = big_number_pow(ten.clone(), exp10.clone()).unwrap();
        assert_eq!(big_number_string(result), "10000000000");

        let base_dec = big_number_new("2.5".to_string()).unwrap();
        let exp2 = big_number_new("2".to_string()).unwrap();
        let result = big_number_pow(base_dec.clone(), exp2.clone()).unwrap();
        assert_eq!(big_number_string(result), "6.25");

        let neg_exp = big_number_new("-1".to_string()).unwrap();

        assert!(big_number_pow(base.clone(), neg_exp.clone()).is_err());
    }

    #[test]
    fn test_big_number_absolute() {
        let positive = big_number_new("123".to_string()).unwrap();
        let result = big_number_absolute(positive.clone()).unwrap();
        assert_eq!(big_number_string(result), "123");

        let negative = big_number_new("-456".to_string()).unwrap();
        let result = big_number_absolute(negative.clone()).unwrap();
        assert_eq!(big_number_string(result), "456");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_absolute(zero.clone()).unwrap();
        assert_eq!(big_number_string(result), "0");

        let pos_dec = big_number_new("123.45".to_string()).unwrap();
        let result = big_number_absolute(pos_dec.clone()).unwrap();
        assert_eq!(big_number_string(result), "123.45");

        let neg_dec = big_number_new("-123.45".to_string()).unwrap();
        let result = big_number_absolute(neg_dec.clone()).unwrap();
        assert_eq!(big_number_string(result), "123.45");
    }
}
