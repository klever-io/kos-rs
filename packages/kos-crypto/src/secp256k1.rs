use kos_types::error::Error;

use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Error as Secp256k1Error, Message, PublicKey, Secp256k1, SecretKey,
};
use std::{fmt, str::FromStr};

use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[wasm_bindgen]
pub struct Secp256k1KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
    compressed: bool,
}

impl Secp256k1KeyPair {
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: rand::Rng + ?Sized,
    {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(rng);
        Self {
            secret_key,
            public_key,
            compressed: false,
        }
    }

    pub fn new(secret: [u8; 32]) -> Self {
        let secp = Secp256k1::new();

        let secret_key: SecretKey = SecretKey::from_slice(secret.as_ref()).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Self {
            secret_key,
            public_key,
            compressed: false,
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
        let derived_priv_key = m.derive_key(d, password)?;
        let key: &coins_bip32::prelude::SigningKey = derived_priv_key.as_ref();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(key.to_bytes().as_mut())?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(Self {
            secret_key,
            public_key,
            compressed: false,
        })
    }
}

impl Secp256k1KeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        if self.compressed {
            self.public_key.serialize().to_vec()
        } else {
            self.public_key.serialize_uncompressed()[1..].to_vec()
        }
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key[..].to_vec()
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    pub fn set_compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }
}

impl Secp256k1KeyPair {
    pub fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::new();
        let message = Message::from_slice(digest).unwrap();
        let sig = secp.sign_ecdsa_recoverable(&message, &self.secret_key);

        let (rec_id, compact) = sig.serialize_compact();
        let mut raw = vec![0; 65];
        raw[0..64].copy_from_slice(&compact);
        raw[64] = (rec_id.to_i32() & 0xff) as u8;
        raw
    }

    pub fn recover(digest: &[u8], sig: &[u8]) -> Result<Vec<u8>, Error> {
        // check signature length
        if sig.len() != 65 {
            return Err(Secp256k1Error::InvalidSignature.into());
        }

        let secp = secp256k1::Secp256k1::new();
        let recid = RecoveryId::from_i32(sig[64] as i32)?;
        let rec_sig = RecoverableSignature::from_compact(&sig[0..64], recid)?;
        let message = Message::from_slice(digest)?;
        let public_key = secp.recover_ecdsa(&message, &rec_sig)?;
        Ok(public_key.serialize_uncompressed()[1..].to_vec())
    }
}

impl fmt::Debug for Secp256k1KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.secret_key)
            .field(&self.public_key)
            .finish()
    }
}
