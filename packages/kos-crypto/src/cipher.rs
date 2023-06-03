use kos_types::error::Error;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Pbkdf2,
};
use pem::Pem;
use rand::Rng;
use sha2::Sha256;

const KEY_SIZE: usize = 32; // SALTSIZE
const NONCE_SIZE: usize = 12; // NONCESIZE

const ITERATIONS: u32 = 10000;

pub fn to_pem(tag: String, data: &[u8]) -> Result<Pem, Error> {
    Ok(Pem::new(tag, data))
}

pub fn from_pem(pem: Pem) -> Vec<u8> {
    pem.contents().to_vec()
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
        .expect("Error deriving key");
    key
}

pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
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
        .map_err(|e| Error::CipherError(format!("encryption failed: {}", e)))?;

    // Create PEM
    let mut result = salt.to_vec();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    if encrypted.len() < KEY_SIZE + NONCE_SIZE {
        return Err(Error::CipherError("Invalid PEM data".to_owned()));
    }
    let salt = &encrypted[..KEY_SIZE];
    let nonce = &encrypted[KEY_SIZE..KEY_SIZE + NONCE_SIZE];
    let encrypted_data = &encrypted[KEY_SIZE + NONCE_SIZE..];
    let derived_key = derive_key(&salt, password);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(&Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| Error::CipherError(format!("decryption failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"hello world";
        let password = "password";

        let encrypted = encrypt(data, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_password() {
        let data = b"hello world";
        let password = "password";

        let encrypted = encrypt(data, password).unwrap();
        let decrypted = decrypt(&encrypted, "invalid password");
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_data() {
        let data = b"hello world";
        let password = "password";

        let encrypted = encrypt(data, password).unwrap();
        let decrypted = decrypt(&encrypted[..encrypted.len() - 1], password);
        assert!(decrypted.is_err());
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
