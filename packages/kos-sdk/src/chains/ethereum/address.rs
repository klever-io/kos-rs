use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;

use hex::FromHex;
use rlp::{DecoderError, Rlp};
use std::{fmt, str::FromStr};
use web3::types::Address as Web3Address;

use wasm_bindgen::prelude::*;

const ADDRESS_LEN: usize = 20;

#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen(js_name = "ETHAddress")]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Address of a public key.
    pub fn from_public(public: [u8; 64]) -> Address {
        let digest = kos_crypto::hash::keccak256(&public);

        let mut raw = [0u8; ADDRESS_LEN];
        raw.copy_from_slice(&digest[digest.len() - ADDRESS_LEN..]);

        Address(raw)
    }

    /// Address of a private key.
    pub fn from_keypair(kp: &KeyPair) -> Address {
        Address::from_public(kp.public_key().try_into().unwrap())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(raw: &[u8]) -> &Address {
        assert!(raw.len() == ADDRESS_LEN);

        unsafe { std::mem::transmute(&raw[0]) }
    }

    /// To hex address
    pub fn to_hex_address(self) -> String {
        Address::to_hex_checksum(&hex::encode(self.0))
    }

    pub fn to_hex_checksum(address: &str) -> String {
        let address = address.trim_start_matches("0x").to_lowercase();

        let address_hash = hex::encode(kos_crypto::hash::keccak256(address.as_bytes()));

        address
            .char_indices()
            .fold(String::from("0x"), |mut acc, (index, address_char)| {
                // this cannot fail since it's Keccak256 hashed
                let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

                if n > 7 {
                    // make char uppercase if ith character is 9..f
                    acc.push_str(&address_char.to_uppercase().to_string())
                } else {
                    // already lowercased
                    acc.push(address_char)
                }

                acc
            })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_hex_address().fmt(f)
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
                "invalid length, {}",
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
        // remove "0x"|"0X" if exists
        let s = if s.len() > 2 && (s.starts_with("0x") || s.starts_with("0X")) {
            &s[2..]
        } else {
            s
        };

        if s.len() == 40 {
            return Vec::from_hex(s)
                .map_err(|e| Error::InvalidAddress(e.to_string()))
                .and_then(Address::try_from);
        }

        eprintln!("len={} prefix={:x}", s.len(), s.as_bytes()[0]);
        Err(Error::InvalidAddress(
            "invalid ethereum address".to_string(),
        ))
    }
}

// NOTE: AsRef<[u8]> implies ToHex
impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl rlp::Decodable for Address {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let mut data: Vec<u8> = rlp.as_val()?;
        let mut bytes: [u8; ADDRESS_LEN] = [0; ADDRESS_LEN];
        while data.len() < ADDRESS_LEN {
            data.push(0);
        }
        bytes.copy_from_slice(&data[..]);
        Ok(Address(bytes))
    }
}

impl TryFrom<&Web3Address> for Address {
    type Error = Error;

    fn try_from(value: &Web3Address) -> Result<Self, Self::Error> {
        Address::try_from(value.as_bytes())
    }
}

impl From<Address> for Web3Address {
    fn from(value: Address) -> Self {
        Web3Address::from(value.0)
    }
}
