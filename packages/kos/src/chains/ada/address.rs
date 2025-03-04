use crate::chains::ChainError;
use crate::crypto::hash::blake244_digest;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bech32::{u5, Variant};

pub enum AddressType {
    Base,
    Pointer,
    Enterprise,
}

impl AddressType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0..=3 => AddressType::Base,
            4..=5 => AddressType::Pointer,
            _ => AddressType::Enterprise,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            AddressType::Base => 0,
            AddressType::Pointer => 4,
            AddressType::Enterprise => 6,
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum CredentialType {
    Key,
    Script,
}

#[derive(Clone)]
pub struct StakeCredential {
    _type: CredentialType,
    key_hash: Option<[u8; 28]>,
    script_hash: Option<[u8; 28]>,
}

impl StakeCredential {
    pub fn new(pbk: &[u8]) -> Self {
        let key_hash = blake244_digest(pbk);
        StakeCredential::from_key_hash(key_hash)
    }

    pub fn from_key_hash(key_hash: [u8; 28]) -> Self {
        StakeCredential {
            _type: CredentialType::Key,
            key_hash: Some(key_hash),
            script_hash: None,
        }
    }

    pub fn get_hash(&self) -> Result<[u8; 28], ChainError> {
        match self._type {
            CredentialType::Key => match self.key_hash {
                Some(hash) => Ok(hash),
                None => Err(ChainError::InvalidCredential),
            },
            CredentialType::Script => match self.script_hash {
                Some(hash) => Ok(hash),
                None => Err(ChainError::InvalidCredential),
            },
        }
    }
}

pub struct Address {
    pub network: u8,
    pub _type: u8,
    pub payment_cred: Option<StakeCredential>,
    pub stake_cred: Option<StakeCredential>,
    //TODO: Pointer attrs
}

impl Address {
    pub fn serialize(&self) -> Result<Vec<u8>, ChainError> {
        let mut addr_bytes = vec![(self._type << 4) | self.network];
        let addr_type = AddressType::from_u8(self._type);
        match addr_type {
            AddressType::Base => {
                let payment_cred = self
                    .payment_cred
                    .as_ref()
                    .ok_or(ChainError::InvalidCredential)?;
                let stake_cred = self
                    .stake_cred
                    .as_ref()
                    .ok_or(ChainError::InvalidCredential)?;
                addr_bytes.append(&mut payment_cred.get_hash()?.to_vec());
                addr_bytes.append(&mut stake_cred.get_hash()?.to_vec());
                Ok(addr_bytes)
            }
            AddressType::Enterprise => {
                let payment_cred = self
                    .payment_cred
                    .as_ref()
                    .ok_or(ChainError::InvalidCredential)?;
                addr_bytes.append(&mut payment_cred.get_hash()?.to_vec());
                Ok(addr_bytes)
            }
            AddressType::Pointer => Err(ChainError::NotSupported),
        }
    }

    pub fn encode_bech32(&self) -> Result<String, ChainError> {
        let addr_bytes = self.serialize()?;
        let addr_encoded = bech32::convert_bits(addr_bytes.as_ref(), 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::new();
        for i in addr_encoded {
            addr_u5.push(u5::try_from_u8(i)?);
        }
        let res = bech32::encode("addr", addr_u5, Variant::Bech32)?;
        Ok(res)
    }
}
