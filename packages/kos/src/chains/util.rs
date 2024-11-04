use crate::chains::ChainError;
use alloc::vec::Vec;

pub fn slice_from_vec<const N: usize>(vec: &Vec<u8>) -> Result<[u8; N], ChainError> {
    if vec.len() < N {
        return Err(ChainError::InvalidMessageSize);
    }

    let mut arr: [u8; N] = [0; N];
    arr.copy_from_slice(&vec[..]);
    Ok(arr)
}

pub fn private_key_from_vec<const N: usize>(vec: &Vec<u8>) -> Result<[u8; N], ChainError> {
    return slice_from_vec::<N>(vec).map_err(|_| ChainError::InvalidPrivateKey);
}

