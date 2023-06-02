use kos_types::error::Error;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use pem::Pem;
use rand::Rng;
use sha2::Sha256;

const KEY_SIZE: usize = 32; // SALTSIZE
const NONCE_SIZE: usize = 12; // NONCESIZE

const ITERATIONS: u32 = 10000;

pub fn derive_key(salt: &[u8], password: &str) -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATIONS, &mut key)
        .expect("Error deriving key");
    key
}

pub fn encrypt(data: &[u8], password: &str, tag: &str) -> Result<Pem, Error> {
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

    Ok(Pem::new(tag, result))
}

pub fn decrypt(pem: Pem, password: &str) -> Result<Vec<u8>, Error> {
    let all = pem.contents();
    if all.len() < KEY_SIZE + NONCE_SIZE {
        return Err(Error::CipherError("Invalid PEM data".to_owned()));
    }
    let salt = &all[..KEY_SIZE];
    let nonce = &all[KEY_SIZE..KEY_SIZE + NONCE_SIZE];
    let encrypted_data = &all[KEY_SIZE + NONCE_SIZE..];
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
        let tag = "tag";

        let pem = encrypt(data, password, tag).unwrap();
        let decrypted = decrypt(pem, password).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_password() {
        let data = b"hello world";
        let password = "password";
        let tag = "tag";

        let pem = encrypt(data, password, tag).unwrap();
        let decrypted = decrypt(pem, "invalid password");
        assert!(decrypted.is_err());
    }
}
