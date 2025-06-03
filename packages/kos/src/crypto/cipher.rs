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

use argon2::password_hash::{rand_core::OsRng as Argon2OsRng, SaltString as Argon2SaltString};
use argon2::{Argon2, PasswordHash as Argon2PasswordHash, PasswordVerifier};

use super::base64::{simple_base64_decode, simple_base64_encode, wrap_base64};

const KEY_SIZE: usize = 32; // SALTSIZE
const NONCE_SIZE: usize = 12; // NONCESIZE
const IV_SIZE: usize = 16; // IVSIZE
const BLOCK_SIZE: usize = 16; // BLOCKSIZE
const ARGON2_SALT_SIZE: usize = 16; // 128 bits for Argon2 salt

#[derive(Debug, Clone)]
pub enum CipherAlgo {
    GCM = 0,
    GCMArgon2 = 3,
    CBC = 1,
    CFB = 2,
}

/// Argon2id configuration presets based on OWASP recommendations
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Argon2Config {
    /// m=47104 (46 MiB), t=1, p=1 - Highest memory, lowest time
    HighMemory,
    /// m=19456 (19 MiB), t=2, p=1 - Balanced
    Balanced,
    /// m=12288 (12 MiB), t=3, p=1 - Medium memory
    Medium,
    /// m=9216 (9 MiB), t=4, p=1 - Lower memory
    Low,
    /// m=7168 (7 MiB), t=5, p=1 - Lowest memory, highest time
    LowMemory,
}

impl Argon2Config {
    pub fn params(&self) -> (u32, u32, u32) {
        match self {
            Self::HighMemory => (47104, 1, 1), // 46 MiB
            Self::Balanced => (19456, 2, 1),   // 19 MiB
            Self::Medium => (12288, 3, 1),     // 12 MiB
            Self::Low => (9216, 4, 1),         // 9 MiB
            Self::LowMemory => (7168, 5, 1),   // 7 MiB
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(Self::HighMemory),
            1 => Ok(Self::Balanced),
            2 => Ok(Self::Medium),
            3 => Ok(Self::Low),
            4 => Ok(Self::LowMemory),
            _ => Err(ChainError::CipherError("Invalid Argon2 config".to_string())),
        }
    }
}

impl CipherAlgo {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            CipherAlgo::GCM => vec![0],
            CipherAlgo::GCMArgon2 => vec![3],
            CipherAlgo::CBC => vec![1],
            CipherAlgo::CFB => vec![2],
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(CipherAlgo::GCM),
            3 => Ok(CipherAlgo::GCMArgon2),
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
        argon2_config: Option<Argon2Config>,
    ) -> Result<Vec<u8>, ChainError> {
        match self {
            CipherAlgo::GCM => gcm_encrypt(data, password, iterations),
            CipherAlgo::GCMArgon2 => {
                let config = argon2_config.unwrap_or(Argon2Config::Balanced);
                gcm_encrypt_argon2(data, password, config)
            }
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
            CipherAlgo::GCMArgon2 => gcm_decrypt_argon2(data, password),
            CipherAlgo::CBC => cbc_decrypt(data, password, iterations),
            CipherAlgo::CFB => cfb_decrypt(data, password, iterations),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedPem {
    pub label: String,
    pub is_encrypted: bool,
    pub cipher_info: Option<String>,
    pub data: Vec<u8>,
}

impl EncryptedPem {
    pub fn new_encrypted(
        label: String,
        data: &[u8],
        password: &str,
        iterations: u32,
        algo: CipherAlgo,
        argon2_config: Option<Argon2Config>,
    ) -> Result<Self, ChainError> {
        let encrypted_data = encrypt(algo.clone(), data, password, iterations, argon2_config)?;

        Ok(EncryptedPem {
            label,
            is_encrypted: true,
            cipher_info: Some(format!(
                "AES-256-{}",
                match algo {
                    CipherAlgo::GCM => "GCM",
                    CipherAlgo::GCMArgon2 => "GCM-ARGON2",
                    CipherAlgo::CBC => "CBC",
                    CipherAlgo::CFB => "CFB",
                }
            )),
            data: encrypted_data,
        })
    }

    pub fn new_unencrypted(label: String, data: Vec<u8>) -> Self {
        EncryptedPem {
            label,
            is_encrypted: false,
            cipher_info: None,
            data,
        }
    }

    pub fn to_pem_string(&self) -> Result<String, ChainError> {
        let base64_data = wrap_base64(&simple_base64_encode(&self.data), 64)?;

        if self.is_encrypted {
            Ok(format!(
                "-----BEGIN {}-----\n\
             Proc-Type: 4,ENCRYPTED\n\
             DEK-Info: {},\n\
             \n\
             {}\n\
             -----END {}-----",
                self.label,
                self.cipher_info
                    .as_ref()
                    .unwrap_or(&"AES-256-CBC".to_string()),
                base64_data,
                self.label
            ))
        } else {
            Ok(format!(
                "-----BEGIN {}-----\n\
             {}\n\
             -----END {}-----",
                self.label, base64_data, self.label
            ))
        }
    }

    pub fn from_pem_string(pem_data: &str) -> Result<Self, ChainError> {
        let lines: Vec<&str> = pem_data.lines().collect();
        let mut label = String::new();
        let mut is_encrypted = false;
        let mut cipher_info = None;
        let mut data_start = 0;
        let mut data_end = lines.len();

        for (i, line) in lines.iter().enumerate() {
            let trimmed_line = line.trim_start();

            if trimmed_line.starts_with("-----BEGIN ") {
                label = trimmed_line
                    .replace("-----BEGIN ", "")
                    .replace("-----", "")
                    .trim()
                    .to_string();
            } else if trimmed_line.starts_with("Proc-Type: 4,ENCRYPTED") {
                is_encrypted = true;
            } else if trimmed_line.starts_with("DEK-Info: ") {
                cipher_info = Some(
                    trimmed_line
                        .replace("DEK-Info: ", "")
                        .replace(",", "")
                        .trim()
                        .to_string(),
                );
            } else if trimmed_line.trim().is_empty() && data_start == 0 {
                data_start = i + 1;
            } else if trimmed_line.starts_with("-----END") {
                data_end = i;
                break;
            }
        }

        let base64_data = lines[data_start..data_end]
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<&str>>()
            .join("");

        let data = simple_base64_decode(&base64_data)
            .map_err(|e| ChainError::CipherError(format!("Base64 decode error: {}", e)))?;

        Ok(EncryptedPem {
            label,
            is_encrypted,
            cipher_info,
            data,
        })
    }

    pub fn decrypt(&self, password: &str, iterations: u32) -> Result<Vec<u8>, ChainError> {
        if !self.is_encrypted {
            return Ok(self.data.clone());
        }

        decrypt(&self.data, password, iterations)
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

/// Encrypt data and wrap it in a password-protected PEM format
pub fn encrypt_to_pem(
    algo: CipherAlgo,
    data: &[u8],
    password: &str,
    iterations: u32,
    pem_label: &str,
    argon2_config: Option<Argon2Config>,
) -> Result<String, ChainError> {
    let encrypted_data = encrypt(algo.clone(), data, password, iterations, argon2_config)?;

    let wrapped_base64 = wrap_base64(&simple_base64_encode(&encrypted_data), 64)?;

    let pem_string = format!(
        "-----BEGIN {}-----\n\
         Proc-Type: 4,ENCRYPTED\n\
         DEK-Info: AES-256-{},\n\
         \n\
         {}\n\
         -----END {}-----",
        pem_label,
        match algo {
            CipherAlgo::GCM => "GCM",
            CipherAlgo::GCMArgon2 => "GCM-ARGON2",
            CipherAlgo::CBC => "CBC",
            CipherAlgo::CFB => "CFB",
        },
        wrapped_base64,
        pem_label
    );

    Ok(pem_string)
}

/// Decrypt data from a password-protected PEM format
pub fn decrypt_from_pem(
    pem_data: &str,
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    let lines: Vec<&str> = pem_data.lines().collect();
    let mut is_encrypted = false;
    let mut data_start = 0;
    let mut data_end = lines.len();

    for (i, line) in lines.iter().enumerate() {
        let trimmed_line = line.trim_start();

        if trimmed_line.starts_with("-----BEGIN") {
            continue;
        } else if trimmed_line.starts_with("Proc-Type: 4,ENCRYPTED") {
            is_encrypted = true;
        } else if trimmed_line.starts_with("DEK-Info:") {
            // Skip DEK-Info line
            continue;
        } else if trimmed_line.trim().is_empty() {
            // Empty line after headers, data starts next
            if data_start == 0 {
                data_start = i + 1;
            }
        } else if trimmed_line.starts_with("-----END") {
            data_end = i;
            break;
        }
    }

    if !is_encrypted {
        let pem = string_to_pem(pem_data)?;
        return Ok(from_pem(pem));
    }

    let base64_data = lines[data_start..data_end]
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<&str>>()
        .join("");

    let encrypted_data = simple_base64_decode(&base64_data)
        .map_err(|e| ChainError::CipherError(format!("Base64 decode error: {}", e)))?;

    decrypt(&encrypted_data, password, iterations)
}

/// Create a password-protected PEM file for private keys
pub fn create_encrypted_private_key_pem(
    private_key_data: &[u8],
    password: &str,
    iterations: u32,
    algo: CipherAlgo,
    argon2_config: Option<Argon2Config>,
) -> Result<String, ChainError> {
    encrypt_to_pem(
        algo,
        private_key_data,
        password,
        iterations,
        "ENCRYPTED PRIVATE KEY",
        argon2_config,
    )
}

/// Load and decrypt a password-protected private key PEM
pub fn load_encrypted_private_key_pem(
    pem_data: &str,
    password: &str,
    iterations: u32,
) -> Result<Vec<u8>, ChainError> {
    decrypt_from_pem(pem_data, password, iterations)
}

/// Create a password-protected PEM file for certificates with custom data
pub fn create_encrypted_certificate_pem(
    cert_data: &[u8],
    password: &str,
    iterations: u32,
    algo: CipherAlgo,
    argon2_config: Option<Argon2Config>,
) -> Result<String, ChainError> {
    encrypt_to_pem(
        algo,
        cert_data,
        password,
        iterations,
        "ENCRYPTED CERTIFICATE",
        argon2_config,
    )
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

/// Create a password hash using Argon2 for checksum verification
pub fn create_checksum_argon2(password: &str) -> Result<String, ChainError> {
    let salt = Argon2SaltString::generate(&mut Argon2OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ChainError::CipherError(format!("Argon2 hash creation failed: {}", e)))?;

    Ok(password_hash.to_string())
}

/// Verify a password against an Argon2 hash
pub fn check_checksum_argon2(password: &str, checksum: &str) -> Result<bool, ChainError> {
    let parsed_hash = Argon2PasswordHash::new(checksum)
        .map_err(|e| ChainError::CipherError(format!("Invalid hash format: {}", e)))?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn derive_key(salt: &[u8], password: &str, iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key)
        .expect("ChainError deriving key");
    key
}

/// Derive a key using Argon2id
fn derive_key_argon2(
    salt: &[u8],
    password: &str,
    config: Argon2Config,
) -> Result<Vec<u8>, ChainError> {
    let (memory_cost, time_cost, parallelism) = config.params();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            memory_cost,    // memory cost in KB
            time_cost,      // time cost (iterations)
            parallelism,    // parallelism (threads)
            Some(KEY_SIZE), // output length
        )
        .map_err(|e| ChainError::CipherError(format!("Argon2 params error: {}", e)))?,
    );

    let mut key = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| ChainError::CipherError(format!("Argon2 key derivation failed: {}", e)))?;

    Ok(key)
}

pub fn encrypt(
    algo: CipherAlgo,
    data: &[u8],
    password: &str,
    iterations: u32,
    argon2_config: Option<Argon2Config>,
) -> Result<Vec<u8>, ChainError> {
    algo.encrypt(data, password, iterations, argon2_config)
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

/// Encrypt data using AES-256-GCM with Argon2 key derivation
pub fn gcm_encrypt_argon2(
    data: &[u8],
    password: &str,
    config: Argon2Config,
) -> Result<Vec<u8>, ChainError> {
    let salt: [u8; ARGON2_SALT_SIZE] = rand::thread_rng().gen();
    let derived_key = derive_key_argon2(&salt, password, config)?;
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| ChainError::CipherError(format!("GCM encryption failed: {}", e)))?;

    // Format: [algorithm_id][config_id][salt][nonce][ciphertext]
    let mut result = CipherAlgo::GCMArgon2.to_vec();
    result.push(config as u8);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM with Argon2 key derivation
pub fn gcm_decrypt_argon2(encrypted: &[u8], password: &str) -> Result<Vec<u8>, ChainError> {
    if encrypted.len() < 1 + ARGON2_SALT_SIZE + NONCE_SIZE + 1 {
        return Err(ChainError::CipherError(
            "Invalid encrypted data: too short".to_string(),
        ));
    }

    let config = Argon2Config::from_u8(encrypted[0])?;
    let salt = &encrypted[1..1 + ARGON2_SALT_SIZE];
    let nonce = &encrypted[1 + ARGON2_SALT_SIZE..1 + ARGON2_SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[1 + ARGON2_SALT_SIZE + NONCE_SIZE..];

    let derived_key = derive_key_argon2(salt, password, config)?;
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| ChainError::CipherError(format!("GCM decryption failed: {}", e)))
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

    const ITERATIONS: u32 = 600_000;
    const ARGON2ID_CONFIG: Option<super::Argon2Config> = Some(super::Argon2Config::Balanced);

    #[test]
    fn test_encrypt_decrypt() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.clone(), data, password, ITERATIONS, None).unwrap();
            let decrypted = decrypt(&encrypted, password, ITERATIONS).unwrap();
            assert_eq!(data, decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypt_decrypt_argon2() {
        let data = b"Hello, World! This is a test message for Argon2 encryption.";
        let password = "test_password_123";

        for config in [
            Argon2Config::HighMemory,
            Argon2Config::Balanced,
            Argon2Config::Medium,
            Argon2Config::Low,
            Argon2Config::LowMemory,
        ] {
            let encrypted = encrypt(
                CipherAlgo::GCMArgon2,
                data,
                password,
                0, // iterations unused for Argon2
                Some(config),
            )
            .unwrap();

            let decrypted = decrypt(&encrypted, password, 0).unwrap();
            assert_eq!(data, decrypted.as_slice());
        }
    }

    #[test]
    fn test_argon2_config_serialization() {
        let test_cases = [
            (Argon2Config::HighMemory, 0u8),
            (Argon2Config::Balanced, 1u8),
            (Argon2Config::Medium, 2u8),
            (Argon2Config::Low, 3u8),
            (Argon2Config::LowMemory, 4u8),
        ];

        for (config, expected_byte) in test_cases.iter() {
            let config_byte = *config as u8;
            assert_eq!(config_byte, *expected_byte);

            let deserialized = Argon2Config::from_u8(config_byte).unwrap();
            assert_eq!(*config as u8, deserialized as u8);
        }

        assert!(Argon2Config::from_u8(255).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_password() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo, data, password, ITERATIONS, None).unwrap();
            let decrypted = decrypt(&encrypted, "invalid password", ITERATIONS);
            match decrypted {
                Ok(decrypted) => {
                    assert_ne!(data, decrypted.as_slice());
                }
                _ => {} // Expected failure
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_argon2_invalid_password() {
        let data = b"secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt(
            CipherAlgo::GCMArgon2,
            data,
            password,
            0,
            Some(Argon2Config::Balanced),
        )
        .unwrap();

        let result = decrypt(&encrypted, wrong_password, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_invalid_data() {
        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let data = b"hello world";
            let password = "password";

            let encrypted = encrypt(algo.clone(), data, password, ITERATIONS, None).unwrap();
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
    fn test_encrypt_decrypt_argon2_invalid_data() {
        let data = b"test data";
        let password = "password";

        let encrypted = encrypt(
            CipherAlgo::GCMArgon2,
            data,
            password,
            0,
            Some(Argon2Config::Balanced),
        )
        .unwrap();

        let result = decrypt(&encrypted[..encrypted.len() - 5], password, 0);
        assert!(result.is_err());
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
    fn test_create_checksum_argon2() {
        let password = "test_password_123";
        let checksum = create_checksum_argon2(password).unwrap();
        assert!(check_checksum_argon2(password, &checksum).unwrap());

        assert!(!check_checksum_argon2("wrong_password", &checksum).unwrap());
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

        // Modify the cipher text
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

    #[test]
    fn test_encrypt_decrypt_pem() {
        let data = b"This is test private key data";
        let password = "test_password";

        for algo in vec![CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let pem_string = encrypt_to_pem(
                algo.clone(),
                data,
                password,
                ITERATIONS,
                "TEST PRIVATE KEY",
                ARGON2ID_CONFIG,
            )
            .unwrap();

            assert!(pem_string.contains("-----BEGIN TEST PRIVATE KEY-----"));
            assert!(pem_string.contains("Proc-Type: 4,ENCRYPTED"));
            assert!(pem_string.contains("DEK-Info: AES-256-"));

            let decrypted = decrypt_from_pem(&pem_string, password, ITERATIONS).unwrap();
            assert_eq!(data, decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypted_pem_structure() {
        let data = b"Certificate data here";
        let password = "secure_password";

        let encrypted_pem = EncryptedPem::new_encrypted(
            "CERTIFICATE".to_string(),
            data,
            password,
            ITERATIONS,
            CipherAlgo::GCM,
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let pem_string = encrypted_pem.to_pem_string().unwrap();

        let parsed_pem = EncryptedPem::from_pem_string(&pem_string).unwrap();
        assert!(parsed_pem.is_encrypted);
        assert_eq!(parsed_pem.label, "CERTIFICATE");

        let decrypted = parsed_pem.decrypt(password, ITERATIONS).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_private_key_pem_functions() {
        let key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let password = "key_password";

        let pem_string = create_encrypted_private_key_pem(
            key_data,
            password,
            ITERATIONS,
            CipherAlgo::CBC,
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let decrypted_key =
            load_encrypted_private_key_pem(&pem_string, password, ITERATIONS).unwrap();

        assert_eq!(key_data, decrypted_key.as_slice());
    }

    #[test]
    fn test_wrong_password_pem() {
        let data = b"sensitive data";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let pem_string = encrypt_to_pem(
            CipherAlgo::GCM,
            data,
            password,
            ITERATIONS,
            "SECRET DATA",
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let result = decrypt_from_pem(&pem_string, wrong_password, ITERATIONS);
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_with_leading_whitespace() {
        let data = b"test data for encryption";
        let password = "test_password";
        let iterations = 10000;

        let normal_pem = encrypt_to_pem(
            CipherAlgo::GCM,
            data,
            password,
            iterations,
            "TEST KEY",
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let indented_pem = normal_pem
            .lines()
            .map(|line| format!("    {}", line)) // Add 4 spaces to each line
            .collect::<Vec<String>>()
            .join("\n");

        let normal_result = decrypt_from_pem(&normal_pem, password, iterations).unwrap();
        let indented_result = decrypt_from_pem(&indented_pem, password, iterations).unwrap();

        assert_eq!(normal_result, data);
        assert_eq!(indented_result, data);
        assert_eq!(normal_result, indented_result);
    }

    #[test]
    fn test_pem_with_mixed_whitespace() {
        let data = b"sensitive key data";
        let password = "secure_password";
        let iterations = 10000;

        let normal_pem = encrypt_to_pem(
            CipherAlgo::CBC,
            data,
            password,
            iterations,
            "PRIVATE KEY",
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let mixed_whitespace_pem = normal_pem
            .lines()
            .enumerate()
            .map(|(i, line)| {
                if i % 2 == 0 {
                    format!("  {}", line) // Even lines: 2 spaces
                } else {
                    format!("\t{} ", line) // Odd lines: tab + trailing space
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        let result = decrypt_from_pem(&mixed_whitespace_pem, password, iterations).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encrypted_pem_with_whitespace() {
        let data = b"certificate data";
        let password = "cert_password";
        let iterations = 10000;

        let encrypted_pem = EncryptedPem::new_encrypted(
            "CERTIFICATE".to_string(),
            data,
            password,
            iterations,
            CipherAlgo::GCM,
            ARGON2ID_CONFIG,
        )
        .unwrap();

        let pem_string = encrypted_pem.to_pem_string().unwrap();

        let indented_pem = pem_string
            .lines()
            .map(|line| format!("  {}", line))
            .collect::<Vec<String>>()
            .join("\n");

        let parsed_pem = EncryptedPem::from_pem_string(&indented_pem).unwrap();
        assert!(parsed_pem.is_encrypted);
        assert_eq!(parsed_pem.label, "CERTIFICATE");

        let decrypted = parsed_pem.decrypt(password, iterations).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_base64_lines_with_whitespace() {
        let test_pem = r#"    -----BEGIN TEST-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-GCM,

        SGVsbG9X
        b3JsZEhl
        bGxvV29y
        bGQ=
    -----END TEST-----"#;

        let result = EncryptedPem::from_pem_string(test_pem);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert!(parsed.is_encrypted);
        assert_eq!(parsed.label, "TEST");
    }

    #[test]
    fn test_cipher_algo_serialization() {
        let test_cases = [
            (CipherAlgo::GCM, 0u8),
            (CipherAlgo::CBC, 1u8),
            (CipherAlgo::CFB, 2u8),
            (CipherAlgo::GCMArgon2, 3u8),
        ];

        for (algo, expected_byte) in test_cases.iter() {
            let serialized = algo.to_vec();
            assert_eq!(serialized, vec![*expected_byte]);

            let deserialized = CipherAlgo::from_u8(*expected_byte).unwrap();
            assert_eq!(algo.to_vec(), deserialized.to_vec());
        }

        assert!(CipherAlgo::from_u8(255).is_err());
    }

    #[test]
    fn test_argon2_params() {
        let test_cases = vec![
            (Argon2Config::HighMemory, (47104, 1, 1)),
            (Argon2Config::Balanced, (19456, 2, 1)),
            (Argon2Config::Medium, (12288, 3, 1)),
            (Argon2Config::Low, (9216, 4, 1)),
            (Argon2Config::LowMemory, (7168, 5, 1)),
        ];

        for (config, expected_params) in test_cases {
            assert_eq!(config.params(), expected_params);
        }
    }

    #[test]
    fn test_compatibility_between_algorithms() {
        let data = b"test data for compatibility check";
        let password = "test_password";

        let gcm_encrypted = encrypt(CipherAlgo::GCM, data, password, ITERATIONS, None).unwrap();
        let cbc_encrypted = encrypt(CipherAlgo::CBC, data, password, ITERATIONS, None).unwrap();
        let cfb_encrypted = encrypt(CipherAlgo::CFB, data, password, ITERATIONS, None).unwrap();
        let argon2_encrypted = encrypt(
            CipherAlgo::GCMArgon2,
            data,
            password,
            0,
            Some(Argon2Config::Balanced),
        )
        .unwrap();

        assert_ne!(gcm_encrypted, cbc_encrypted);
        assert_ne!(gcm_encrypted, cfb_encrypted);
        assert_ne!(gcm_encrypted, argon2_encrypted);
        assert_ne!(cbc_encrypted, cfb_encrypted);
        assert_ne!(cbc_encrypted, argon2_encrypted);
        assert_ne!(cfb_encrypted, argon2_encrypted);

        assert_eq!(decrypt(&gcm_encrypted, password, ITERATIONS).unwrap(), data);
        assert_eq!(decrypt(&cbc_encrypted, password, ITERATIONS).unwrap(), data);
        assert_eq!(decrypt(&cfb_encrypted, password, ITERATIONS).unwrap(), data);
        assert_eq!(decrypt(&argon2_encrypted, password, 0).unwrap(), data);
    }

    #[test]
    fn test_empty_data_encryption() {
        let empty_data = b"";
        let password = "test_password";

        for algo in [CipherAlgo::GCM, CipherAlgo::CBC, CipherAlgo::CFB] {
            let encrypted = encrypt(algo.clone(), empty_data, password, ITERATIONS, None).unwrap();
            let decrypted = decrypt(&encrypted, password, ITERATIONS).unwrap();
            assert_eq!(empty_data, decrypted.as_slice());
        }

        let encrypted = encrypt(
            CipherAlgo::GCMArgon2,
            empty_data,
            password,
            0,
            Some(Argon2Config::Balanced),
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, password, 0).unwrap();
        assert_eq!(empty_data, decrypted.as_slice());
    }

    #[test]
    fn test_large_data_encryption() {
        let large_data = vec![0x42u8; 1024 * 1024];
        let password = "test_password";

        let encrypted = encrypt(CipherAlgo::GCM, &large_data, password, 10000, None).unwrap();

        let decrypted = decrypt(&encrypted, password, 10000).unwrap();
        assert_eq!(large_data, decrypted);
    }
}
