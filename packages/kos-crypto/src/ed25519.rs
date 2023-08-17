use kos_types::{error::Error, Bytes32};

use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::{fmt, str::FromStr};

use wasm_bindgen::prelude::wasm_bindgen;

type HmacSha521 = Hmac<Sha512>;

#[derive(serde::Serialize, serde::Deserialize)]
#[wasm_bindgen]
pub struct Ed25519KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
}

impl Default for Ed25519KeyPair {
    fn default() -> Self {
        Self {
            secret_key: SigningKey::from_bytes(&[0u8; SECRET_KEY_LENGTH]),
            public_key: VerifyingKey::from_bytes(&[0u8; PUBLIC_KEY_LENGTH]).unwrap(),
        }
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Ed25519KeyPair {
        Ed25519KeyPair {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

impl Ed25519KeyPair {
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: rand::Rng + ?Sized,
    {
        let mut secret = Bytes32::zeroed();
        rng.fill(secret.as_mut());

        Ed25519KeyPair::new(secret.into())
    }

    pub fn new(secret: [u8; 32]) -> Self {
        let secret_key: SigningKey = SigningKey::from_bytes(&secret);
        let public_key: VerifyingKey = (&secret_key).into();

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn new_from_mnemonic_phrase_with_path(
        phrase: &str,
        path: &str,
        password: Option<&str>,
    ) -> Result<Self, Error> {
        let mnemonic = Mnemonic::<English>::new_from_phrase(phrase)?;
        let path = DerivationPath::from_str(path)?;
        Self::new_from_mnemonic(path, mnemonic, password)
    }

    /// Generate a new secret key from a `DerivationPath` and `Mnemonic`.
    pub fn new_from_mnemonic(
        d: DerivationPath,
        m: Mnemonic<English>,
        password: Option<&str>,
    ) -> Result<Self, Error> {
        let seed = m.to_seed(password.as_deref())?;

        let hardened_child_padding: u8 = 0;
        let mut digest =
            HmacSha521::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
        digest.update(&seed);
        let intermediary: Vec<u8> = digest
            .finalize()
            .into_bytes()
            .into_iter()
            .map(|x| x)
            .collect();
        let mut key = intermediary[..SECRET_KEY_LENGTH].to_vec();
        let mut chain_code = intermediary[SECRET_KEY_LENGTH..].to_vec();

        for child_idx in d.iter() {
            let mut buff = [vec![hardened_child_padding], key.clone()].concat();
            buff.push((child_idx >> 24) as u8);
            buff.push((child_idx >> 16) as u8);
            buff.push((child_idx >> 8) as u8);
            buff.push((child_idx & 0xff) as u8);

            digest =
                HmacSha521::new_from_slice(&chain_code).expect("HMAC can take key of any size");
            digest.update(&buff);
            let intermediary: Vec<u8> = digest
                .finalize()
                .into_bytes()
                .into_iter()
                .map(|x| x)
                .collect();
            key = intermediary[..SECRET_KEY_LENGTH].to_vec();
            chain_code = intermediary[SECRET_KEY_LENGTH..].to_vec();
        }

        Ok(Self::new(key.try_into().map_err(|_e| {
            Error::InvalidMnemonic("Error convert vec into slice")
        })?))
    }
}

impl Ed25519KeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }
}

impl Ed25519KeyPair {
    pub fn sign_digest(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.secret_key.sign(message);
        sig.to_bytes().to_vec()
    }

    pub fn verify_digest(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let mut pub_bytes = [0u8; 32];
        if public_key.len() != 32 {
            pub_bytes = self.public_key.to_bytes();
        } else {
            pub_bytes.copy_from_slice(public_key);
        }

        VerifyingKey::from_bytes(&pub_bytes)
            .map(|public_key| {
                public_key
                    .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                    .is_ok()
            })
            .is_ok()
    }
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.secret_key)
            .field(&self.public_key)
            .finish()
    }
}
