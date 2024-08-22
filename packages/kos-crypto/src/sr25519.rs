use std::str::FromStr;
use coins_bip32::path::DerivationPath;
use kos_types::{error::Error, Bytes32};
use coins_bip39::{English, Mnemonic};
use subxt_signer::{sr25519, sr25519::Keypair};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
pub struct Sr25519KeyPair {
    keypair: Keypair
}

impl Serialize for Sr25519KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {

        Ok(serializer.serialize_str("Sr25519KeyPair )")?)
    }
}

impl<'de> Deserialize<'de> for Sr25519KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        Ok(Sr25519KeyPair::default())
    }
}

impl Default for Sr25519KeyPair {
    fn default() -> Self {
        Self {
            keypair: Keypair::from_seed(sr25519::Seed::from([0u8; 32])).unwrap()
        }
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
        let seed = sr25519::Seed::from(secret);
        let keypair = Keypair::from_seed(seed).unwrap();

        Self {
            keypair
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

        let seed = sr25519::Seed::from(key.to_bytes());
        let keypair = Keypair::from_seed(seed).unwrap();
        Ok(Self {
            keypair
        })
    }
}

impl Sr25519KeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().0.to_vec()
    }
}

impl Sr25519KeyPair {
    pub fn sign_digest(&self, message: &[u8]) -> Vec<u8> {
        // let keypair = Keypair::from_seed()
        // let keypair = Keypair {
        //     secret: sr25519::Secret(self.secret_key.clone()),
        //     public: self.public_key,
        // };
        // keypair.sign(message).0.to_vec()
        Vec::new()
    }

    pub fn verify_digest(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        // let keypair = Keypair {
        //     secret: sr25519::Secret(self.secret_key.clone()),
        //     public: self.public_key,
        // };
        // verify(&keypair, message, signature)
        true
    }
}
