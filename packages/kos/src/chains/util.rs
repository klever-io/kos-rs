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
