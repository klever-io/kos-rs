use crate::chains::ChainError;
use alloc::vec::Vec;

pub fn slice_from_vec<const N: usize>(vec: &[u8]) -> Result<[u8; N], ChainError> {
    if vec.len() < N {
        return Err(ChainError::InvalidMessageSize);
    }

    let mut arr: [u8; N] = [0; N];
    arr.copy_from_slice(vec);
    Ok(arr)
}

pub fn private_key_from_vec<const N: usize>(vec: &[u8]) -> Result<[u8; N], ChainError> {
    // If input is longer than N, take first N bytes
    let slice = if vec.len() > N { &vec[..N] } else { vec };

    slice_from_vec::<N>(slice).map_err(|_| ChainError::InvalidPrivateKey)
}

pub fn hex_string_to_vec(hex: &str) -> Result<Vec<u8>, ChainError> {
    let hex = hex.trim_start_matches("0x");
    hex::decode(hex).map_err(|_| ChainError::InvalidHex)
}
pub fn byte_vectors_to_bytes(data: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = Vec::new();

    let num_vecs = (data.len() as u32).to_le_bytes();
    result.extend_from_slice(&num_vecs);

    for vec in data {
        let vec_len = (vec.len() as u32).to_le_bytes();
        result.extend_from_slice(&vec_len);

        result.extend_from_slice(vec);
    }

    result
}
pub fn bytes_to_byte_vectors(bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, ChainError> {
    if bytes.len() < 4 {
        return Err(ChainError::InvalidMessageSize);
    }

    let mut result = Vec::new();
    let mut position = 0;

    let num_vecs = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    position += 4;

    for _ in 0..num_vecs {
        if position + 4 > bytes.len() {
            return Err(ChainError::InvalidMessageSize);
        }

        let vec_len = u32::from_le_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        position += 4;

        if position + vec_len > bytes.len() {
            return Err(ChainError::InvalidMessageSize);
        }

        let vec_data = bytes[position..position + vec_len].to_vec();
        result.push(vec_data);
        position += vec_len;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hex_string_to_vec() {
        let hex_str = "0x1234567890abcdef";
        let result = hex_string_to_vec(hex_str).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_hex_strings_to_bytes() {
        let hex_strings = vec![hex::decode("db41e41de474e2cb6d997ae5aa5de9aa81512a19d1337881363a3c481431935992a118ba863b6d00612c638b5caf7bac65cb2cf31a7d30f9c5473fcb97bf620bc006bf0760963c13c1c1478adbc326b96338060f03487ebd1c3b261dbccd8daf").unwrap(), hex::decode("db41e41de8163a3c481431935992a118ba863b6d00612c638b5caf7bac65cb2c7ebd1c3b261dbccd8daf").unwrap()];
        let result = byte_vectors_to_bytes(&hex_strings);

        let decoded = bytes_to_byte_vectors(result).unwrap();
        assert_eq!(hex_strings, decoded);
    }
}
