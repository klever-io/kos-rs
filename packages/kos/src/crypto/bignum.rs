use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::f64;
use core::fmt::Write;
use rlp::{DecoderError, Rlp, RlpStream};

pub struct U256(pub [u8; 32]);

impl Clone for U256 {
    fn clone(&self) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        bytes.copy_from_slice(&self.0[..]);
        U256(bytes)
    }
}

impl rlp::Decodable for U256 {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data: Vec<u8> = rlp.as_val()?;

        let val = U256::read_data_as_le(data.clone());

        Ok(val)
    }
}

impl rlp::Encodable for U256 {
    fn rlp_append(&self, s: &mut RlpStream) {
        //Copy data as the reverse of the bytes removing the leading zeroes
        let to_put = self.put_data_as_le();

        s.encoder().encode_value(&to_put);
    }
}

impl U256 {
    #[allow(dead_code)]
    pub fn from_f64(value: f64, precision: u32) -> Result<U256, &'static str> {
        if value.is_nan() || value.is_infinite() || value < 0.0 {
            return Err("Invalid input: NaN, infinity, or negative value.");
        }

        let scaled_value = value * powi(10.0, precision as i32);
        if scaled_value > (u64::MAX as f64) {
            return Err("Input too large to fit in U256.");
        }

        let integer_value = scaled_value as u64;
        Ok(U256::from_u64(integer_value))
    }

    #[allow(clippy::needless_range_loop)]
    pub fn to_f64(&self, precision: u32) -> f64 {
        let bytes = self.0;
        let mut value: f64 = 0.0;

        for i in 0..32 {
            value *= 256.0;
            value += bytes[i] as f64;
        }

        value /= powi(10.0, precision as i32);
        value
    }

    pub fn from_i64(value: i64) -> U256 {
        let value = value as u64;
        U256::from_u64(value)
    }

    pub fn from_u64(value: u64) -> U256 {
        let mut bytes: [u8; 32] = [0; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    #[allow(dead_code)]
    pub fn from_string(value: &str) -> Result<U256, &'static str> {
        if value.len() > 64 {
            return Err("String length exceeds U256 size.");
        }

        let mut padded = String::new();
        for _ in 0..(64 - value.len()) {
            // Zero-padding to ensure 64 characters.
            padded.push('0');
        }
        padded.push_str(value);

        let bytes = hex::decode(&padded).map_err(|_| "Invalid hex string")?;
        let mut data = [0u8; 32];
        data.copy_from_slice(&bytes);
        Ok(U256(data))
    }

    #[allow(clippy::inherent_to_string)]
    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        let mut hex_string = String::new();
        for byte in self.0.iter() {
            write!(&mut hex_string, "{byte:02x}").unwrap(); // Safely format bytes as hex.
        }

        let trimmed = hex_string.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    }

    #[allow(dead_code)]
    pub fn to_u64_be(&self) -> u64 {
        let bytes = self.0;
        let mut significant_part = [0u8; 8];
        significant_part.copy_from_slice(&bytes[24..32]);
        u64::from_be_bytes(significant_part)
    }

    #[allow(clippy::manual_memcpy)]
    #[allow(dead_code)]
    pub fn read_data_as_be(data: Vec<u8>) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        let len = data.len().min(32);
        for i in 0..len {
            bytes[i] = data[i];
        }

        U256(bytes)
    }

    pub fn read_data_as_le(data: Vec<u8>) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        let len = data.len();
        for i in 0..len {
            bytes[i] = data[len - 1 - i];
        }

        U256(bytes)
    }

    #[allow(dead_code)]
    pub fn put_data_as_be(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        for i in 0..32 {
            data.push(self.0[i]);
        }

        data
    }

    #[allow(clippy::needless_range_loop)]
    pub fn put_data_as_le(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        //find the end of the data
        for i in 0..32 {
            data.push(self.0[31 - i]);
        }

        //Trim the leading zeroes
        let mut start = data.len();
        for i in 0..32 {
            if data[i] != 0 {
                start = i;
                break;
            }
        }

        data = data[start..].to_vec();
        data
    }
}

fn powi(f: f64, exp: i32) -> f64 {
    let mut result = 1.0;
    let mut base = f;
    let mut exponent = exp;

    if exponent < 0 {
        base = 1.0 / base;
        exponent = -exponent;
    }

    while exponent > 0 {
        if exponent % 2 == 1 {
            result *= base;
        }
        base *= base;
        exponent /= 2;
    }

    result
}

#[cfg(test)]
mod test {
    use crate::crypto::bignum::U256;

    #[test]
    fn test_f64_conversion() {
        let mut value = U256([0x0; 32]);
        value.0[31] = 0x01;
        let precision = 6;
        let float_value = value.to_f64(precision);
        assert_eq!(float_value, 1e-6);

        let reconstructed = U256::from_f64(float_value, precision).unwrap();
        assert_eq!(reconstructed.0, value.0);

        let large_value = 12345.6789;
        let large_precision = 4;
        let u256_value = U256::from_f64(large_value, large_precision).unwrap();
        let back_to_f64 = u256_value.to_f64(large_precision);
        assert_eq!(back_to_f64, large_value);
    }

    #[test]
    fn test_string_conversion() {
        let value = U256::from_u64(123456789);
        let hex_string = value.to_string();
        assert_eq!(hex_string, "75bcd15");

        let parsed = U256::from_string(&hex_string).unwrap();
        assert_eq!(parsed.0, value.0);
    }
}
