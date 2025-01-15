use blake2b_ref::Blake2bBuilder;
use sha2::digest::FixedOutput;
use sha2::Digest;

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::default();
    hasher.update(data);
    let mut hash: [u8; 32] = [0; 32];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}

#[allow(dead_code)]
pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut hasher = sha2::Sha512::default();
    hasher.update(data);
    let mut hash: [u8; 64] = [0; 64];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}

#[allow(dead_code)]
pub fn sha3_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(data);
    let mut hash: [u8; 32] = [0; 32];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}

pub fn keccak256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::default();
    hasher.update(data);
    let mut hash: [u8; 32] = [0; 32];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}

pub fn blake2b_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bBuilder::new(32).build();
    hasher.update(data);

    let mut result_buffer: [u8; 32] = [0; 32];
    hasher.finalize(result_buffer.as_mut_slice());
    result_buffer
}

pub fn blake244_digest(data: &[u8]) -> [u8; 28] {
    let mut hasher = Blake2bBuilder::new(28).build();
    hasher.update(data);

    let mut result_buffer: [u8; 28] = [0; 28];
    hasher.finalize(result_buffer.as_mut_slice());
    result_buffer
}

pub fn blake2b_64_digest(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2bBuilder::new(64).build();
    hasher.update(data);

    let mut result_buffer: [u8; 64] = [0; 64];
    hasher.finalize(result_buffer.as_mut_slice());
    result_buffer
}

pub fn ripemd160_digest(data: &[u8]) -> [u8; 20] {
    let input_md = sha256_digest(data);
    let mut hasher = ripemd::Ripemd160::default();
    hasher.update(input_md);
    let mut hash: [u8; 20] = [0; 20];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}

pub fn sha224_digest(data: &[u8]) -> [u8; 28] {
    let mut hasher = sha2::Sha224::default();
    hasher.update(data);
    let mut hash: [u8; 28] = [0; 28];
    let out = hasher.finalize_fixed();
    hash.copy_from_slice(&out[..]);
    hash
}
