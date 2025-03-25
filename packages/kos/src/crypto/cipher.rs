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
use hmac::Hmac;
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

const ITERATIONS: u32 = 10000;

#[derive(Debug, Clone)]
pub enum CipherAlgo {
    GMC = 0,
    CBC = 1,
    CFB = 2,
}

impl CipherAlgo {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            CipherAlgo::GMC => vec![0],
            CipherAlgo::CBC => vec![1],
            CipherAlgo::CFB => vec![2],
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(CipherAlgo::GMC),
            1 => Ok(CipherAlgo::CBC),
            2 => Ok(CipherAlgo::CFB),
            _ => Err(ChainError::CipherError(
                "Invalid cipher algorithm".to_owned(),
            )),
        }
    }

    pub fn encrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
        match self {
            CipherAlgo::GMC => gcm_encrypt(data, password),
            CipherAlgo::CBC => cbc_encrypt(data, password),
            CipherAlgo::CFB => cfb_encrypt(data, password),
        }
    }

    pub fn decrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
        match self {
            CipherAlgo::GMC => gcm_decrypt(data, password),
            CipherAlgo::CBC => cbc_decrypt(data, password),
            CipherAlgo::CFB => cfb_decrypt(data, password),
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

pub fn derive_key(salt: &[u8], password: &str) -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATIONS, &mut key)
        .expect("ChainError deriving key");
    key
}

pub fn encrypt(algo: CipherAlgo, data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    algo.encrypt(data, password)
}

pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    if data.is_empty() {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }

    // get algo
    let algo = CipherAlgo::from_u8(data[0])?;
    algo.decrypt(&data[1..], password)
}

pub fn gcm_encrypt(data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    // Derive key from password
    let salt: [u8; 32] = rand::thread_rng().gen();
    let derived_key = derive_key(&salt, password);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);

    // Generate a unique nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt data
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| ChainError::CipherError(format!("encryption failed: {}", e)))?;

    // Create PEM
    let mut result = CipherAlgo::GMC.to_vec();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn gcm_decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < KEY_SIZE + NONCE_SIZE {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }
    let salt = &encrypted[..KEY_SIZE];
    let nonce = &encrypted[KEY_SIZE..KEY_SIZE + NONCE_SIZE];
    let encrypted_data = &encrypted[KEY_SIZE + NONCE_SIZE..];
    let derived_key = derive_key(salt, password);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| ChainError::CipherError(format!("decryption failed: {}", e)))
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
pub fn cbc_encrypt(data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    let iv: [u8; IV_SIZE] = rand::thread_rng().gen();
    let derived_key = derive_key(&iv, password); //  KeySize [u8; 32]
    let key = GenericArray::from_slice(&derived_key);

    let padding_size = BLOCK_SIZE - data.len() % BLOCK_SIZE;
    let buf_len = data.len() + padding_size;

    let mut buf = vec![0; buf_len];

    buf[..data.len()].copy_from_slice(data);

    let ct = Aes256CbcEnc::new(key, &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .map_err(|e| ChainError::CipherError(format!("encryption failed: {}", e)))?;

    // Create PEM
    let mut result = CipherAlgo::CBC.to_vec();
    result.extend_from_slice(&iv);
    result.extend_from_slice(ct);

    Ok(result)
}

pub fn cbc_decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < IV_SIZE {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }

    let iv = GenericArray::from_slice(&encrypted[..IV_SIZE]);
    let encrypted_data = &encrypted[IV_SIZE..];
    let derived_key = derive_key(iv, password);
    let key = GenericArray::from_slice(&derived_key);

    let mut buf = encrypted_data.to_vec();
    let pt: &[u8] = Aes256CbcDec::new(key, iv)
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| ChainError::CipherError(format!("decryption failed: {}", e)))?;

    Ok(pt.to_vec())
}

type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;
pub fn cfb_encrypt(data: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    let iv: [u8; IV_SIZE] = rand::thread_rng().gen();
    let derived_key = derive_key(&iv, password); //  KeySize [u8; 32]
    let key = GenericArray::from_slice(&derived_key);

    let mut buf = data.to_vec();
    Aes256CfbEnc::new(key, &iv.into()).encrypt(&mut buf);

    // Create PEM
    let mut result = CipherAlgo::CFB.to_vec();
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buf);

    Ok(result)
}

pub fn cfb_decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < IV_SIZE {
        return Err(ChainError::CipherError("Invalid PEM data".to_owned()));
    }

    let iv = GenericArray::from_slice(&encrypted[..IV_SIZE]);
    let encrypted_data = &encrypted[IV_SIZE..];
    let derived_key = derive_key(iv, password);
    let key = GenericArray::from_slice(&derived_key);

    let mut buf = encrypted_data.to_vec();
    Aes256CfbDec::new(key, iv).decrypt(&mut buf);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        for algo in vec![CipherAlgo::GMC, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.to_owned(), data, password).unwrap();
            let decrypted = decrypt(&encrypted, password).unwrap();
            assert_eq!(data, decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypt_decrypt_invalid_password() {
        for algo in vec![CipherAlgo::GMC, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo, data, password).unwrap();
            let decrypted = decrypt(&encrypted, "invalid password");
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
        for algo in vec![CipherAlgo::GMC, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.clone(), data, password).unwrap();
            let decrypted = decrypt(&encrypted[..encrypted.len() - 1], password);
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
}
