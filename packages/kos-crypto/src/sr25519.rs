use coins_bip39::{English, Mnemonic};
use kos_types::{error::Error, Bytes32};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_core::{sr25519, Pair};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct Sr25519KeyPair {
    keypair: sr25519::Pair,
}

impl Serialize for Sr25519KeyPair {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de> Deserialize<'de> for Sr25519KeyPair {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

impl Clone for Sr25519KeyPair {
    fn clone(&self) -> Sr25519KeyPair {
        Sr25519KeyPair {
            keypair: self.keypair.clone(),
        }
    }
}

impl Sr25519KeyPair {
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: rand::Rng + ?Sized,
    {
        let mut secret = Bytes32::zeroed();
        rng.fill(secret.as_mut());

        Sr25519KeyPair::new(secret.into())
    }

    pub fn new(secret: [u8; 32]) -> Self {
        let keypair = sr25519::Pair::from_seed_slice(&secret).unwrap();
        Self { keypair }
    }

    pub fn new_from_mnemonic_phrase_with_path(
        phrase: &str,
        path: &str,
        password: Option<&str>,
    ) -> Result<Self, Error> {
        let mnemonic = Mnemonic::<English>::new_from_phrase(phrase)?;
        Self::new_from_mnemonic(path, mnemonic, password)
    }

    pub fn new_from_mnemonic(
        path: &str,
        m: Mnemonic<English>,
        password: Option<&str>,
    ) -> Result<Self, Error> {
        // Convert mnemonic to seed
        let seed = format!("{}{}", m.to_phrase(), path);

        // Derive keypair based on the provided path and seed
        let keypair = Pair::from_string(&seed, password).unwrap();

        Ok(Self { keypair })
    }
}

impl Sr25519KeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public().0.to_vec()
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.keypair.to_raw_vec()
    }
}

impl Sr25519KeyPair {
    pub fn sign_digest(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message).0.to_vec()
    }

    pub fn verify_digest(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        let public = sr25519::Public::from_raw(<[u8; 32]>::try_from(public_key).unwrap());

        let signature = sr25519::Signature::from_raw(<[u8; 64]>::try_from(signature).unwrap());

        sr25519::Pair::verify(&signature, message, &public)
    }
}
