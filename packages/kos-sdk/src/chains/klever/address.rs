use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;

use bech32::{FromBase32, ToBase32};
use hex::FromHex;
use std::{fmt, str::FromStr};

use wasm_bindgen::prelude::*;

const ADDRESS_LEN: usize = 32;
const ADDRESS_HRP: &str = "klv";

#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen(js_name = "KLVAddress")]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Address of a public key.
    pub fn from_public(public: [u8; 32]) -> Address {
        // pubkey to address use first 32 bytes
        Address(public)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0
    }

    /// Address of a keypair.
    pub fn from_keypair(kp: &KeyPair) -> Address {
        Address::from_public(kp.public_key().try_into().unwrap())
    }

    /// As raw 32-byte address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Address from raw 32-byte.
    pub fn from_bytes(raw: &[u8]) -> &Address {
        assert!(raw.len() == ADDRESS_LEN);

        unsafe { std::mem::transmute(&raw[0]) }
    }

    /// To hex address
    pub fn to_hex_address(&self) -> String {
        hex::encode(self.0)
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let st = bech32::encode(ADDRESS_HRP, self.0.to_base32(), bech32::Variant::Bech32).unwrap();
        st.fmt(f)
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
            Err(Error::InvalidAddress(format!(
                "invalid length: {}",
                value.len()
            )))
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
        if s.starts_with(ADDRESS_HRP) {
            return bech32::decode(s)
                .map_err(|e| Error::InvalidAddress(e.to_string()))
                .and_then(|(_, data, _)| {
                    Vec::from_base32(&data)
                        .map_err(|e| Error::InvalidAddress(e.to_string()))
                        .and_then(Address::try_from)
                });
        }

        if s.len() == 64 {
            return Vec::from_hex(s)
                .map_err(|e| Error::InvalidAddress(e.to_string()))
                .and_then(Address::try_from);
        }

        if s.len() == 66 && (s.starts_with("0x") || s.starts_with("0X")) {
            return Vec::from_hex(&s.as_bytes()[2..])
                .map_err(|e| Error::InvalidAddress(e.to_string()))
                .and_then(Address::try_from);
        }

        if s == "_" || s == "0x0" || s == "/0" {
            return Ok(Address([0u8; ADDRESS_LEN]));
        }

        eprintln!("len={} prefix={:x}", s.len(), s.as_bytes()[0]);
        Err(Error::InvalidAddress("invalid klever address".to_string()))
    }
}

// NOTE: AsRef<[u8]> implies ToHex
impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
