use crate::KOSError;
use bigdecimal::BigDecimal;
use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, Pow, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Default, Serialize, Deserialize, uniffi::Record)]
pub struct BigNumber {
    pub value: String,
}

// Helper function to format BigRational as decimal when necessary
fn format_big_rational(rat: &BigRational) -> String {
    // Return only numerator if denominator is 1 (integer case)
    if rat.denom() == &BigInt::one() {
        return rat.numer().to_string();
    }

    let numer = rat.numer();
    let denom = rat.denom();

    let (quotient, remainder) = numer.div_rem(denom);

    if remainder.is_zero() {
        return quotient.to_string();
    }

    let mut decimal = quotient.to_string();
    decimal.push('.');

    let mut rem = remainder.abs();
    let den = denom.abs();
    let mut decimal_digits = String::new();

    // Precision limit to prevent infinite loops (e.g., for numbers like 1/3)
    let precision_limit = 20;
    let mut i = 0;

    while !rem.is_zero() && i < precision_limit {
        rem *= 10;
        let (digit, new_rem) = rem.div_rem(&den);
        decimal_digits.push_str(&digit.to_string());
        rem = new_rem;
        i += 1;
    }

    // Remove trailing zeros
    while decimal_digits.ends_with('0') && decimal_digits.len() > 1 {
        decimal_digits.pop();
    }

    decimal.push_str(&decimal_digits);
    decimal
}

impl BigNumber {
    pub fn new(value: &str) -> Result<Self, KOSError> {
        if value.is_empty() {
            return Err(KOSError::KOSNumber("Invalid number".to_string()));
        }

        // Parse the value to check if it's a valid number
        let parsed_value = match BigDecimal::from_str(value) {
            Ok(num) => num.to_string(), // Convert to string to avoid precision loss
            Err(_) => return Err(KOSError::KOSNumber("Invalid number format".to_string())),
        };

        Ok(BigNumber {
            value: parsed_value,
        })
    }

    pub fn to_bigint(&self) -> Result<BigInt, KOSError> {
        if let Ok(int) = BigInt::from_str(&self.value) {
            return Ok(int);
        }

        match BigRational::from_str(&self.value) {
            Ok(rat) => Ok(rat.to_integer()),
            Err(_) => Err(KOSError::KOSNumber("Invalid number".to_string())),
        }
    }

    pub fn to_bigrational(&self) -> Result<BigRational, KOSError> {
        if let Ok(rat) = BigRational::from_str(&self.value) {
            return Ok(rat);
        }

        if let Ok(int) = BigInt::from_str(&self.value) {
            return Ok(BigRational::from(int));
        }

        // Manual parsing for decimal values
        if self.value.contains('.') {
            let parts: Vec<&str> = self.value.split('.').collect();
            if parts.len() != 2 {
                return Err(KOSError::KOSNumber("Invalid decimal format".to_string()));
            }

            let integer_part = parts[0];
            let decimal_part = parts[1];

            let is_negative = integer_part.starts_with('-');
            let int_abs = if is_negative {
                &integer_part[1..]
            } else {
                integer_part
            };

            // Construct numerator and denominator
            let numerator_str = format!(
                "{}{}{}",
                if is_negative { "-" } else { "" },
                int_abs,
                decimal_part
            );
            let denominator_str = format!("1{}", "0".repeat(decimal_part.len()));

            match (
                BigInt::from_str(&numerator_str),
                BigInt::from_str(&denominator_str),
            ) {
                (Ok(num), Ok(den)) => Ok(BigRational::new(num, den)),
                _ => Err(KOSError::KOSNumber(
                    "Failed to convert to rational number".to_string(),
                )),
            }
        } else {
            Err(KOSError::KOSNumber("Invalid number format".to_string()))
        }
    }
}

#[uniffi::export]
fn big_number_new(value: String) -> Result<BigNumber, KOSError> {
    BigNumber::new(&value)
}

#[uniffi::export]
fn big_number_add(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer-only operations
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return Ok(BigNumber {
            value: (left + right).to_string(),
        });
    }

    // Fall back to rational operations
    let left = lhs.to_bigrational()?;
    let right = rhs.to_bigrational()?;
    let result = left + right;

    Ok(BigNumber {
        value: format_big_rational(&result),
    })
}

#[uniffi::export]
fn big_number_subtract(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer-only operations
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return Ok(BigNumber {
            value: (left - right).to_string(),
        });
    }

    // Fall back to rational operations
    let left = lhs.to_bigrational()?;
    let right = rhs.to_bigrational()?;
    let result = left - right;

    Ok(BigNumber {
        value: format_big_rational(&result),
    })
}

#[uniffi::export]
fn big_number_multiply(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer-only operations
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return Ok(BigNumber {
            value: (left * right).to_string(),
        });
    }

    // Fall back to rational operations
    let left = lhs.to_bigrational()?;
    let right = rhs.to_bigrational()?;
    let result = left * right;

    Ok(BigNumber {
        value: format_big_rational(&result),
    })
}

#[uniffi::export]
fn big_number_divide(lhs: BigNumber, rhs: BigNumber) -> Result<BigNumber, KOSError> {
    // Check for division by zero
    if big_number_is_zero(rhs.clone()) {
        return Err(KOSError::KOSNumber("Division by zero".to_string()));
    }

    // Check if both are integers and the division is exact
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        if &left % &right == BigInt::zero() {
            return Ok(BigNumber {
                value: (left / right).to_string(),
            });
        }
    }

    // Fall back to rational operations
    let left = lhs.to_bigrational()?;
    let right = rhs.to_bigrational()?;
    let result = left / right;

    Ok(BigNumber {
        value: format_big_rational(&result),
    })
}

#[uniffi::export]
fn big_number_pow(base: BigNumber, exponent: BigNumber) -> Result<BigNumber, KOSError> {
    // Exponent must be a non-negative integer
    let exp = exponent.to_bigint()?;
    if exp.is_negative() {
        return Err(KOSError::KOSNumber(
            "Exponent must be non-negative".to_string(),
        ));
    }

    // Convert to u32 for use with the Pow trait
    let exp_u32 = match exp.to_u32() {
        Some(e) => e,
        None => return Err(KOSError::KOSNumber("Exponent too large".to_string())),
    };

    // Optimize for integer base
    if let Ok(base_int) = BigInt::from_str(&base.value) {
        return Ok(BigNumber {
            value: base_int.pow(exp_u32).to_string(),
        });
    }

    // Fall back to rational base
    let base_rat = base.to_bigrational()?;
    let result = base_rat.pow(exp_u32);

    Ok(BigNumber {
        value: format_big_rational(&result),
    })
}

#[uniffi::export]
fn big_number_is_equal(lhs: BigNumber, rhs: BigNumber) -> bool {
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return left == right;
    }
    lhs.to_bigrational().map_or(false, |left| {
        rhs.to_bigrational().map_or(false, |right| left == right)
    })
}

#[uniffi::export]
fn big_number_is_gt(lhs: BigNumber, rhs: BigNumber) -> bool {
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return left > right;
    }
    lhs.to_bigrational().map_or(false, |left| {
        rhs.to_bigrational().map_or(false, |right| left > right)
    })
}

#[uniffi::export]
fn big_number_is_gte(lhs: BigNumber, rhs: BigNumber) -> bool {
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return left >= right;
    }
    lhs.to_bigrational().map_or(false, |left| {
        rhs.to_bigrational().map_or(false, |right| left >= right)
    })
}

#[uniffi::export]
fn big_number_is_lt(lhs: BigNumber, rhs: BigNumber) -> bool {
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return left < right;
    }
    lhs.to_bigrational().map_or(false, |left| {
        rhs.to_bigrational().map_or(false, |right| left < right)
    })
}

#[uniffi::export]
fn big_number_is_lte(lhs: BigNumber, rhs: BigNumber) -> bool {
    if let (Ok(left), Ok(right)) = (BigInt::from_str(&lhs.value), BigInt::from_str(&rhs.value)) {
        return left <= right;
    }
    lhs.to_bigrational().map_or(false, |left| {
        rhs.to_bigrational().map_or(false, |right| left <= right)
    })
}

#[uniffi::export]
fn big_number_absolute(value: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer cases
    if let Ok(val) = BigInt::from_str(&value.value) {
        return Ok(BigNumber {
            value: val.abs().to_string(),
        });
    }

    // Fall back to rational operations
    let val = value.to_bigrational()?;
    Ok(BigNumber {
        value: format_big_rational(&val.abs()),
    })
}

#[uniffi::export]
fn big_number_is_zero(value: BigNumber) -> bool {
    if let Ok(val) = BigInt::from_str(&value.value) {
        return val.is_zero();
    }
    value.to_bigrational().map_or(false, |val| val.is_zero())
}

#[uniffi::export]
fn big_number_increment(value: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer case
    if let Ok(val) = BigInt::from_str(&value.value) {
        return Ok(BigNumber {
            value: (val + BigInt::one()).to_string(),
        });
    }

    // Fall back to rational operations
    let val = value.to_bigrational()?;
    let result = val + BigRational::from(BigInt::one());

    let value = BigRational::from(result);
    Ok(BigNumber {
        value: format_big_rational(&value),
    })
}

#[uniffi::export]
fn big_number_decrement(value: BigNumber) -> Result<BigNumber, KOSError> {
    // Optimize for integer case
    if let Ok(val) = BigInt::from_str(&value.value) {
        return Ok(BigNumber {
            value: (val - BigInt::one()).to_string(),
        });
    }

    // Fall back to rational operations
    let val = value.to_bigrational()?;
    let result = val - BigRational::from(BigInt::one());

    let value = BigRational::from(result);
    Ok(BigNumber {
        value: format_big_rational(&value),
    })
}

#[uniffi::export]
fn big_number_is_positive(value: BigNumber) -> Result<bool, KOSError> {
    // Optimize for integer case
    if let Ok(val) = BigInt::from_str(&value.value) {
        return Ok(val.is_positive());
    }

    // Fall back to rational operations
    let val = value.to_bigrational()?;
    Ok(val.is_positive())
}

#[uniffi::export]
fn big_number_is_negative(value: BigNumber) -> Result<bool, KOSError> {
    // Optimize for integer case
    if let Ok(val) = BigInt::from_str(&value.value) {
        return Ok(val.is_negative());
    }

    // Fall back to rational operations
    let val = value.to_bigrational()?;
    Ok(val.is_negative())
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
        assert_eq!(result.value, "579");

        let c = big_number_new("-123".to_string()).unwrap();
        let result = big_number_add(b.clone(), c.clone()).unwrap();
        assert_eq!(result.value, "333");

        let d = big_number_new("123.5".to_string()).unwrap();
        let e = big_number_new("456.7".to_string()).unwrap();
        let result = big_number_add(d.clone(), e.clone()).unwrap();
        assert_eq!(result.value, "580.2");

        let result = big_number_add(a.clone(), d.clone()).unwrap();
        assert_eq!(result.value, "246.5");

        let f = big_number_new("123.456".to_string()).unwrap();
        let g = big_number_new("1e5".to_string()).unwrap();
        let result = big_number_add(f.clone(), g.clone()).unwrap();
        assert_eq!(result.value, "100123.456");
    }

    #[test]
    fn test_big_number_subtract() {
        let a = big_number_new("456".to_string()).unwrap();
        let b = big_number_new("123".to_string()).unwrap();
        let result = big_number_subtract(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "333");

        let result = big_number_subtract(b.clone(), a.clone()).unwrap();
        assert_eq!(result.value, "-333");

        let c = big_number_new("456.7".to_string()).unwrap();
        let d = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_subtract(c.clone(), d.clone()).unwrap();
        assert_eq!(result.value, "333.2");

        let result = big_number_subtract(c.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "333.7");
    }

    #[test]
    fn test_big_number_multiply() {
        let a = big_number_new("123".to_string()).unwrap();
        let b = big_number_new("456".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "56088");

        let c = big_number_new("-123".to_string()).unwrap();
        let result = big_number_multiply(c.clone(), b.clone()).unwrap();
        assert_eq!(result.value, "-56088");

        let d = big_number_new("12.3".to_string()).unwrap();
        let e = big_number_new("4.56".to_string()).unwrap();
        let result = big_number_multiply(d.clone(), e.clone()).unwrap();
        assert_eq!(result.value, "56.088");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_multiply(a.clone(), zero.clone()).unwrap();
        assert_eq!(result.value, "0");
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
        assert_eq!(result.value, "3.33333333333333333333");

        let e = big_number_new("12.6".to_string()).unwrap();
        let f = big_number_new("2.1".to_string()).unwrap();
        let result = big_number_divide(e.clone(), f.clone()).unwrap();
        assert_eq!(result.value, "6");

        let zero = big_number_new("0".to_string()).unwrap();
        assert!(big_number_divide(a.clone(), zero.clone()).is_err());
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
        assert_eq!(result.value, "124");

        let b = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_increment(b.clone()).unwrap();
        assert_eq!(result.value, "124.5");

        let c = big_number_new("123".to_string()).unwrap();
        let result = big_number_decrement(c.clone()).unwrap();
        assert_eq!(result.value, "122");

        let d = big_number_new("123.5".to_string()).unwrap();
        let result = big_number_decrement(d.clone()).unwrap();
        assert_eq!(result.value, "122.5");
    }

    #[test]
    fn test_big_number_is_positive_negative() {
        let a = big_number_new("123".to_string()).unwrap();
        assert!(big_number_is_positive(a.clone()).unwrap());
        assert!(!big_number_is_negative(a.clone()).unwrap());

        let b = big_number_new("-456".to_string()).unwrap();
        assert!(!big_number_is_positive(b.clone()).unwrap());
        assert!(big_number_is_negative(b.clone()).unwrap());

        let c = big_number_new("0".to_string()).unwrap();
        assert!(!big_number_is_positive(c.clone()).unwrap());
        assert!(!big_number_is_negative(c.clone()).unwrap());
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
        assert_eq!(result.value, "8");

        let zero = big_number_new("0".to_string()).unwrap();
        let result = big_number_pow(base.clone(), zero.clone()).unwrap();
        assert_eq!(result.value, "1");

        let ten = big_number_new("10".to_string()).unwrap();
        let exp10 = big_number_new("10".to_string()).unwrap();
        let result = big_number_pow(ten.clone(), exp10.clone()).unwrap();
        assert_eq!(result.value, "10000000000");

        let base_dec = big_number_new("2.5".to_string()).unwrap();
        let exp2 = big_number_new("2".to_string()).unwrap();
        let result = big_number_pow(base_dec.clone(), exp2.clone()).unwrap();
        assert_eq!(result.value, "6.25");

        let neg_exp = big_number_new("-1".to_string()).unwrap();

        assert!(big_number_pow(base.clone(), neg_exp.clone()).is_err());
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

        let pos_dec = big_number_new("123.45".to_string()).unwrap();
        let result = big_number_absolute(pos_dec.clone()).unwrap();
        assert_eq!(result.value, "123.45");

        let neg_dec = big_number_new("-123.45".to_string()).unwrap();
        let result = big_number_absolute(neg_dec.clone()).unwrap();
        assert_eq!(result.value, "123.45");
    }
}
