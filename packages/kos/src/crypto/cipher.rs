use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, AsyncStreamCipher, BlockDecryptMut,
    BlockEncryptMut, KeyIvInit,
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit as GCMKeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

use crate::alloc::borrow::ToOwned;
use crate::alloc::string::{String, ToString};
use crate::chains::ChainError;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Pbkdf2,
};
use pem::{parse as parse_pem, Pem};
use rand::Rng;
use sha2::Sha256;

const KEY_SIZE: usize = 32; // SALTSIZE
const NONCE_SIZE: usize = 12; // NONCESIZE
const IV_SIZE: usize = 16; // IVSIZE
const BLOCK_SIZE: usize = 16; // BLOCKSIZE

#[derive(Debug, Clone)]
pub enum CipherAlgo {
    GCM = 0,
    CBC = 1,
    CFB = 2,
}

impl CipherAlgo {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            CipherAlgo::GCM => vec![0],
            CipherAlgo::CBC => vec![1],
            CipherAlgo::CFB => vec![2],
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(CipherAlgo::GCM),
            1 => Ok(CipherAlgo::CBC),
            2 => Ok(CipherAlgo::CFB),
            _ => Err(ChainError::CipherError(
                "Invalid cipher algorithm".to_owned(),
            )),
        }
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        password: &str,
        iterations: u32,
    ) -> Result<Vec<u8>, ChainError> {
        match self {
            CipherAlgo::GCM => gcm_encrypt(data, password, iterations),
            CipherAlgo::CBC => cbc_encrypt(data, password, iterations),
            CipherAlgo::CFB => cfb_encrypt(data, password, iterations),
        }
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        password: &str,
        iterations: u32,
    ) -> Result<Vec<u8>, ChainError> {
        match self {
            CipherAlgo::GCM => gcm_decrypt(data, password, iterations),
            CipherAlgo::CBC => cbc_decrypt(data, password, iterations),
            CipherAlgo::CFB => cfb_decrypt(data, password, iterations),
        }
    }
}

pub fn to_pem(tag: String, data: &[u8]) -> Result<Pem, ChainError> {
    Ok(Pem::new(tag, data))
}

pub fn from_pem(pem: Pem) -> Vec<u8> {
    pem.contents().to_vec()
}

pub fn string_to_pem(data: &str) -> Result<Pem, ChainError> {
    parse_pem(data.as_bytes()).map_err(|e| ChainError::CipherError(format!("{}", e)))
}

pub fn create_checksum(password: &str) -> String {
    let rng = rand::thread_rng();
    let salt = SaltString::generate(rng);
    let password_hash = pbkdf2::Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .unwrap();

    password_hash.to_string()
}

pub fn check_checksum(password: &str, checksum: String) -> bool {
    let parsed_hash = PasswordHash::new(&checksum).unwrap();
    let result = parsed_hash.verify_password(&[&Pbkdf2], password);

    result.is_ok()
}

pub fn derive_key(salt: &[u8], password: &str, iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key)
        .expect("ChainError deriving key");
    key
}

pub fn encrypt(
    algo: CipherAlgo,
    data: &[u8],
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    algo.encrypt(data, password, iterations)
}

pub fn decrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, ChainError> {
    if data.is_empty() {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }

    // get algo
    let algo = CipherAlgo::from_u8(data[0])?;
    algo.decrypt(&data[1..], password, iterations)
}

pub fn gcm_encrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, ChainError> {
    // Derive key from password
    let salt: [u8; 32] = rand::thread_rng().gen();
    let derived_key = derive_key(&salt, password, iterations);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);

    // Generate a unique nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt data
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| ChainError::CipherError(format!("encryption failed: {}", e)))?;

    // Create PEM
    let mut result = CipherAlgo::GCM.to_vec();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn gcm_decrypt(
    encrypted: &[u8],
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < KEY_SIZE + NONCE_SIZE {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }
    let salt = &encrypted[..KEY_SIZE];
    let nonce = &encrypted[KEY_SIZE..KEY_SIZE + NONCE_SIZE];
    let encrypted_data = &encrypted[KEY_SIZE + NONCE_SIZE..];
    let derived_key = derive_key(salt, password, iterations);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| ChainError::CipherError(format!("decryption failed: {}", e)))
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
pub fn cbc_encrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, ChainError> {
    let iv: [u8; IV_SIZE] = rand::thread_rng().gen();
    let derived_key = derive_key(&iv, password, iterations); // KeySize [u8; 32]
    let key = GenericArray::from_slice(&derived_key);

    let padding_size = BLOCK_SIZE - data.len() % BLOCK_SIZE;
    let buf_len = data.len() + padding_size;

    let mut buf = vec![0; buf_len];

    buf[..data.len()].copy_from_slice(data);

    let ct = Aes256CbcEnc::new(key, &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .map_err(|e| ChainError::CipherError(format!("encryption failed: {}", e)))?;

    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(ct);

    let hmac_salt: [u8; 32] = rand::thread_rng().gen();
    let hmac_key = derive_key(&hmac_salt, password, iterations);

    let mut mac: Hmac<Sha256> = <Hmac<Sha256> as KeyInit>::new_from_slice(&hmac_key)
        .map_err(|e| ChainError::CipherError(format!("HMAC creation failed: {}", e)))?;
    mac.update(&hmac_input);
    let hmac_result = mac.finalize().into_bytes();

    let mut result = CipherAlgo::CBC.to_vec();
    result.extend_from_slice(&hmac_salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&hmac_result);
    result.extend_from_slice(ct);

    Ok(result)
}

pub fn cbc_decrypt(
    encrypted: &[u8],
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    let min_length = KEY_SIZE + IV_SIZE + 32; // 32 bytes for HMAC-SHA256
    if encrypted.len() < min_length {
        return Err(ChainError::CipherError("Invalid encrypted data".to_owned()));
    }

    let hmac_salt = &encrypted[0..KEY_SIZE];
    let iv = &encrypted[KEY_SIZE..KEY_SIZE + IV_SIZE];
    let hmac = &encrypted[KEY_SIZE + IV_SIZE..KEY_SIZE + IV_SIZE + 32];
    let ciphertext = &encrypted[KEY_SIZE + IV_SIZE + 32..];

    let hmac_key = derive_key(hmac_salt, password, iterations);

    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(iv);
    hmac_input.extend_from_slice(ciphertext);

    let mut mac: Hmac<Sha256> = <Hmac<Sha256> as KeyInit>::new_from_slice(&hmac_key)
        .map_err(|e| ChainError::CipherError(format!("HMAC creation failed: {}", e)))?;
    mac.update(&hmac_input);

    mac.verify_slice(hmac).map_err(|_| {
        ChainError::CipherError(
            "Invalid authentication tag - data may have been tampered with".to_owned(),
        )
    })?;

    let derived_key = derive_key(iv, password, iterations);
    let key = GenericArray::from_slice(&derived_key);
    let iv_array = GenericArray::from_slice(iv);

    let mut buf = ciphertext.to_vec();
    let pt = Aes256CbcDec::new(key, iv_array)
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| ChainError::CipherError(format!("decryption failed: {}", e)))?;

    Ok(pt.to_vec())
}

type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;
pub fn cfb_encrypt(data: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, ChainError> {
    let iv: [u8; IV_SIZE] = rand::thread_rng().gen();
    let derived_key = derive_key(&iv, password, iterations); //  KeySize [u8; 32]
    let key = GenericArray::from_slice(&derived_key);

    let mut buf = data.to_vec();
    Aes256CfbEnc::new(key, &iv.into()).encrypt(&mut buf);

    // Create PEM
    let mut result = CipherAlgo::CFB.to_vec();
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);

    Ok(result)
}

pub fn cfb_decrypt(
    encrypted: &[u8],
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < IV_SIZE {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }

    let iv = GenericArray::from_slice(&encrypted[..IV_SIZE]);
    let encrypted_data = &encrypted[IV_SIZE..];
    let derived_key = derive_key(iv, password, iterations);
    let key = GenericArray::from_slice(&derived_key);

    let mut buf = encrypted_data.to_vec();
    Aes256CfbDec::new(key, iv).decrypt(&mut buf);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERATIONS: u32 = 10000;

    #[test]
    fn test_encrypt_decrypt() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.to_owned(), data, password, ITERATIONS).unwrap();
            let decrypted = decrypt(&encrypted, password, ITERATIONS).unwrap();
            assert_eq!(data, decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypt_decrypt_invalid_password() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo, data, password, ITERATIONS).unwrap();
            let decrypted = decrypt(&encrypted, "invalid password", ITERATIONS);
            match decrypted {
                Ok(decrypted) => {
                    assert_ne!(data, decrypted.as_slice());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_invalid_data() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.clone(), data, password, ITERATIONS).unwrap();
            let decrypted = decrypt(&encrypted[..encrypted.len() - 1], password, ITERATIONS);
            match decrypted {
                Ok(decrypted) => {
                    assert_ne!(data, decrypted.as_slice());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_to_pem() {
        let data = b"hello world";
        let tag = "TEST";
        let pem = to_pem(tag.to_owned(), data).unwrap();
        assert_eq!(pem.tag(), tag);
        assert_eq!(pem.contents(), data);
    }

    #[test]
    fn test_from_pem() {
        let data = b"hello world";
        let tag = "TEST";
        let pem = to_pem(tag.to_owned(), data).unwrap();
        let pem_data = from_pem(pem);
        assert_eq!(pem_data, data);
    }

    #[test]
    fn test_create_checksum() {
        let password = "password";
        let checksum = create_checksum(password);
        assert!(check_checksum(password, checksum));
    }

    #[test]
    fn test_cbc_bit_flipping_attack() {
        // Given plaintext similar to the example
        let plaintext = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // 32 bytes, exactly two blocks
        let password = "supersecret"; // Password for key derivation

        // Encrypt the username using CBC mode
        let encrypted = cbc_encrypt(plaintext, password, ITERATIONS).unwrap();

        // Simulate the server leaking the ciphertext
        let leaked_ciphertext = encrypted.clone();

        // Perform the bit-flipping attack
        // We want to change one 'b' to 'a'
        // This means we need to flip the first byte of the first ciphertext block

        let xor_value = b'b' ^ b'a'; // XOR between 'b' and 'a'
        let mut tampered_encrypted = leaked_ciphertext.clone();

        // Modify the ciper text
        tampered_encrypted[IV_SIZE + 1] ^= xor_value;

        // Decrypt the tampered ciphertext
        let result = cbc_decrypt(&tampered_encrypted[1..], password, ITERATIONS);

        match result {
            Ok(decrypted) => {
                let original_plaintext = String::from_utf8_lossy(plaintext);
                let decrypted_plaintext = String::from_utf8_lossy(&decrypted);
                assert_eq!(original_plaintext, decrypted_plaintext);
            }
            Err(e) => {
                assert!(e.to_string().contains("cipher error: Invalid authentication tag - data may have been tampered with"), 
                "Decryption failed unexpectedly with error: {}", e);
            }
        }
    }
}
