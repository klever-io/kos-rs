use std::fmt;
use std::str::FromStr;

use kos_crypto::{public::PublicKey, secret::SecretKey};
use kos_types::error::Error;

use hex::FromHex;

use base58::{FromBase58, ToBase58};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

/// The mainnet uses 0x41('A') as address type prefix.
const ADDRESS_TYPE_PREFIX: u8 = 0x41;

/// Address of Tron, saved in 21-byte format.
#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen]
pub struct Address([u8; 21]);

impl Address {
    /// Address of a public key.
    pub fn from_public(public: &PublicKey) -> Address {
        let mut hasher = Keccak256::new();
        hasher.update(public);
        let digest = hasher.finalize();

        let mut raw = [ADDRESS_TYPE_PREFIX; 21];
        raw[1..21].copy_from_slice(&digest[digest.len() - 20..]);

        Address(raw)
    }

    /// Address of a private key.
    pub fn from_private(private: &SecretKey) -> Address {
        let p = PublicKey::from(private);
        Address::from_public(&p)
    }

    /// As raw 21-byte address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// As 20-byte address that compatiable with Ethereum.
    pub fn as_tvm_bytes(&self) -> &[u8] {
        &self.0[1..]
    }

    /// Address from 20-byte address that compatiable with Ethereum.
    pub fn from_tvm_bytes(raw: &[u8]) -> Self {
        assert!(raw.len() == 20);

        let mut inner = [ADDRESS_TYPE_PREFIX; 21];
        inner[1..21].copy_from_slice(raw);
        Address(inner)
    }

    /// Address rom raw 21-byte.
    pub fn from_bytes(raw: &[u8]) -> &Address {
        assert!(raw.len() == 21);

        unsafe { std::mem::transmute(&raw[0]) }
    }

    /// To hex address, i.e. 41-address.
    pub fn to_hex_address(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        b58encode_check(&self.0).fmt(f)
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.debug_tuple("Address").field(&self.to_string()).finish()
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 21 {
            Err(Error::InvalidAddress("invalid length"))
        } else {
            let mut raw = [0u8; 21];
            raw[..21].copy_from_slice(value);
            Ok(Address(raw))
        }
    }
}

impl TryFrom<Vec<u8>> for Address {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&Vec<u8>> for Address {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&str> for Address {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Address::from_str(value)
    }
}

impl FromHex for Address {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Address::try_from(hex.as_ref())
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if s.len() == 34 {
            return b58decode_check(s).and_then(Address::try_from);
        }

        if s.len() == 42 && s[..2] == hex::encode(&[ADDRESS_TYPE_PREFIX]) {
            return Vec::from_hex(s)
                .map_err(|_| Error::InvalidAddress(""))
                .and_then(Address::try_from);
        }

        if s.len() == 44 && (s.starts_with("0x") || s.starts_with("0X")) {
            return Vec::from_hex(&s.as_bytes()[2..])
                .map_err(|_| Error::InvalidAddress(""))
                .and_then(Address::try_from);
        }

        if s == "_" || s == "0x0" || s == "/0" {
            return "410000000000000000000000000000000000000000".parse();
        }

        eprintln!("len={} prefix={:x}", s.len(), s.as_bytes()[0]);
        Err(Error::InvalidAddress("other"))
    }
}

// NOTE: AsRef<[u8]> implies ToHex
impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Base58check encode.
pub fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_ref());
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(digest1);
    let digest2 = hasher.finalize();

    let mut raw = raw.as_ref().to_owned();
    raw.extend(&digest2[..4]);
    raw.to_base58()
}

/// Base58check decode.
pub fn b58decode_check(s: &str) -> Result<Vec<u8>, Error> {
    let mut result = s.from_base58().map_err(|_| Error::InvalidAddress(""))?;

    let check = result.split_off(result.len() - 4);

    let mut hasher = Sha256::new();
    hasher.update(&result);
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&digest1);
    let digest2 = hasher.finalize();

    if check != &digest2[..4] {
        Err(Error::InvalidChecksum("base58check"))
    } else {
        Ok(result)
    }
}
