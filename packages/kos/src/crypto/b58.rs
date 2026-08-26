use crate::chains::ChainError;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

const B58DIGITS_ORDERED: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn custom_b58enc(data: &[u8], alpha: &[u8; 58]) -> Vec<u8> {
    let mut zcount = 0;

    while zcount < data.len() && data[zcount] == 0 {
        zcount += 1;
    }

    let size = (data.len() - zcount) * 138 / 100 + 1;
    let mut buf = vec![0u8; size];

    let mut high = size - 1;
    for (_, &val) in data.iter().enumerate().skip(zcount) {
        let mut carry = val as usize;
        let mut j = size - 1;

        while j > high || carry != 0 {
            carry += 256 * buf[j] as usize;
            buf[j] = (carry % 58) as u8;
            carry /= 58;

            if j == 0 {
                break;
            }
            j -= 1;
        }
        high = j;
    }

    let mut j = 0;
    while j < size && buf[j] == 0 {
        j += 1;
    }

    let mut result = Vec::with_capacity(zcount + size - j);
    result.extend(vec![alpha[0]; zcount]);

    for &val in &buf[j..] {
        result.push(alpha[val as usize]);
    }

    result
}

pub fn b58enc(data: &[u8]) -> Vec<u8> {
    custom_b58enc(data, B58DIGITS_ORDERED)
}

pub fn custom_b58enc_string(data: &[u8], alpha: &[u8; 58]) -> String {
    let bytes = custom_b58enc(data, alpha);
    String::from_utf8_lossy(&bytes).to_string()
}

pub fn b58enc_string(data: &[u8]) -> String {
    custom_b58enc_string(data, B58DIGITS_ORDERED)
}

pub fn custom_b58dec(data: &[u8], alpha: &[u8; 58]) -> Result<Vec<u8>, ChainError> {
    let mut zcount = 0;

    while zcount < data.len() && data[zcount] == alpha[0] {
        zcount += 1;
    }

    let size = (data.len() - zcount) * 733 / 1000 + 1;
    let mut buf = vec![0u8; size];

    for &byte in &data[zcount..] {
        let val = alpha
            .iter()
            .position(|&c| c == byte)
            .ok_or(ChainError::InvalidCharacter(byte as char))?;

        let mut carry = val;
        for b in buf.iter_mut().rev() {
            carry += 58 * (*b as usize);
            *b = (carry % 256) as u8;
            carry /= 256;
        }

        if carry != 0 {
            return Err(ChainError::BufferTooSmall);
        }
    }

    let mut j = 0;
    while j < size && buf[j] == 0 {
        j += 1;
    }

    let mut result = Vec::with_capacity(zcount + (size - j));
    result.extend(vec![0u8; zcount]);
    result.extend_from_slice(&buf[j..]);

    Ok(result)
}

pub fn b58dec(data: &[u8]) -> Result<Vec<u8>, ChainError> {
    custom_b58dec(data, B58DIGITS_ORDERED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b58_encode_decode_roundtrip() {
        let original = b"Hello World!";
        let encoded = b58enc(original);
        let decoded = b58dec(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_b58_leading_zeros() {
        let original = b"\x00\x00\x00test";
        let encoded = b58enc(original);
        assert_eq!(&encoded[..3], b"111");
        let decoded = b58dec(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_b58_invalid_character() {
        let invalid_encoded = b"1230IOl";
        assert!(b58dec(invalid_encoded).is_err());
    }

    #[test]
    fn test_b58enc_string() {
        let original = b"Hello World!";
        let encoded_str = b58enc_string(original);
        assert_eq!(encoded_str, "2NEpo7TZRRrLZSi2U");
        let decoded = b58dec(encoded_str.as_bytes()).unwrap();
        assert_eq!(decoded, original);
    }
}
