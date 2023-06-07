use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;

use base58::{FromBase58, ToBase58};
use hex::FromHex;
use std::{fmt, str::FromStr};

use wasm_bindgen::prelude::*;

/// The mainnet uses 0x41('A') as address type prefix.
const ADDRESS_TYPE_PREFIX: u8 = 0x41;
const ADDRESS_LEN: usize = 21;

/// Address of Tron, saved in 21-byte format.
#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen(js_name = "TRXAddress")]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Address of a public key.
    pub fn from_public(public: [u8; 64]) -> Address {
        let digest = kos_crypto::hash::keccak256(&public);

        let mut raw = [ADDRESS_TYPE_PREFIX; ADDRESS_LEN];
        raw[1..ADDRESS_LEN].copy_from_slice(&digest[digest.len() - 20..]);

        Address(raw)
    }

    /// Address of a private key.
    pub fn from_keypair(kp: &KeyPair) -> Address {
        Address::from_public(kp.public_key().try_into().unwrap())
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

        let mut inner = [ADDRESS_TYPE_PREFIX; ADDRESS_LEN];
        inner[1..ADDRESS_LEN].copy_from_slice(raw);
        Address(inner)
    }

    /// Address from raw 21-byte.
    pub fn from_bytes(raw: &[u8]) -> &Address {
        assert!(raw.len() == ADDRESS_LEN);

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
        if value.len() != ADDRESS_LEN {
            Err(Error::InvalidAddress("invalid length"))
        } else {
            let mut raw = [0u8; ADDRESS_LEN];
            raw[..ADDRESS_LEN].copy_from_slice(value);
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
    let digest1 = kos_crypto::hash::sha256(raw.as_ref());
    let digest2 = kos_crypto::hash::sha256(&digest1);

    let mut raw = raw.as_ref().to_owned();
    raw.extend(&digest2[..4]);
    raw.to_base58()
}

/// Base58check decode.
pub fn b58decode_check(s: &str) -> Result<Vec<u8>, Error> {
    let mut result = s.from_base58().map_err(|_| Error::InvalidAddress(""))?;

    let check = result.split_off(result.len() - 4);
    let digest1 = kos_crypto::hash::sha256(&result);
    let digest2 = kos_crypto::hash::sha256(&digest1);

    if check != &digest2[..4] {
        Err(Error::InvalidChecksum("base58check"))
    } else {
        Ok(result)
    }
}
