use kos_types::{error::Error, Bytes32};

use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use core::{borrow::Borrow, fmt, ops::Deref};
use secp256k1::{Error as Secp256k1Error, SecretKey as Secp256k1SecretKey};
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// Asymmetric secret key
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen]
pub struct SecretKey(Bytes32);

impl SecretKey {
    /// Memory length of the type
    pub const LEN: usize = Bytes32::LEN;

    /// Construct a `SecretKey` directly from its bytes.
    #[inline]
    fn from_bytes_unchecked(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes.into())
    }
}

impl Deref for SecretKey {
    type Target = [u8; SecretKey::LEN];

    fn deref(&self) -> &[u8; SecretKey::LEN] {
        self.0.deref()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<SecretKey> for [u8; SecretKey::LEN] {
    fn from(salt: SecretKey) -> [u8; SecretKey::LEN] {
        salt.0.into()
    }
}

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl SecretKey {
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: rand::Rng + ?Sized,
    {
        let mut secret = Bytes32::zeroed();
        rng.fill(secret.as_mut());
        Self(secret)
    }

    pub fn new_from_mnemonic_phrase_with_path(phrase: &str, path: &str) -> Result<Self, Error> {
        let mnemonic = Mnemonic::<English>::new_from_phrase(phrase)?;
        let path = DerivationPath::from_str(path)?;
        Self::new_from_mnemonic(path, mnemonic)
    }

    /// Generate a new secret key from a `DerivationPath` and `Mnemonic`.
    pub fn new_from_mnemonic(d: DerivationPath, m: Mnemonic<English>) -> Result<Self, Error> {
        let derived_priv_key = m.derive_key(d, None)?;
        let key: &coins_bip32::prelude::SigningKey = derived_priv_key.as_ref();
        let bytes: [u8; Self::LEN] = key.to_bytes().into();
        Ok(SecretKey::from_bytes_unchecked(bytes))
    }
}

impl TryFrom<Bytes32> for SecretKey {
    type Error = Error;

    fn try_from(b: Bytes32) -> Result<Self, Self::Error> {
        secret_key_bytes_valid(&b).map(|_| Self(b))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Bytes32::try_from(slice)
            .map_err(|_| Secp256k1Error::InvalidSecretKey.into())
            .and_then(SecretKey::try_from)
    }
}

impl FromStr for SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bytes32::from_str(s)
            .map_err(|_| Secp256k1Error::InvalidSecretKey.into())
            .and_then(SecretKey::try_from)
    }
}

impl Borrow<Secp256k1SecretKey> for SecretKey {
    fn borrow(&self) -> &Secp256k1SecretKey {
        // Safety: field checked. The memory representation of the secp256k1 key is
        // `[u8; 32]`
        #[allow(unsafe_code)]
        unsafe {
            &*(self.as_ref().as_ptr() as *const Secp256k1SecretKey)
        }
    }
}

/// Check if the secret key byte representation is within the curve.
fn secret_key_bytes_valid(bytes: &[u8; SecretKey::LEN]) -> Result<(), Error> {
    secp256k1::SecretKey::from_slice(bytes)
        .map(|_| ())
        .map_err(Into::into)
}
