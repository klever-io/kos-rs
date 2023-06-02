use crate::blake2b::Blake2b;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

#[inline]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[inline]
pub fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::new(32);
    hasher.update(input);
    hasher.finalize().try_into().unwrap()
}
