use alloc::vec::Vec;
use core::f64;
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
    pub fn to_f64(&self, precision: u32) -> f64 {
        let bytes = self.0;
        let mut value: f64 = 0.0;

        for i in 0..32 {
            value *= 256.0;
            value += bytes[i] as f64;
        }

        value = value / (powi(10.0, precision as i32) as f64);
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
    pub fn to_u64_be(&self) -> u64 {
        let bytes = self.0;
        let mut significant_part = [0u8; 8];
        significant_part.copy_from_slice(&bytes[24..32]);
        u64::from_be_bytes(significant_part)
    }

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
    }
}
