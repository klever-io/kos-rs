use crate::chains::ChainError;
use crate::crypto::bignum::U256;
use aes_gcm::aead::Buffer;
use alloc::vec;
use alloc::vec::Vec;
use parity_scale_codec::{Compact, Decode, Encode, Input};

#[derive(Decode)]
pub struct Call {
    pub _call_index: CallIndex,
    pub args: [u8; 100],
}

#[derive(Decode)]
pub struct CallIndex {
    _section_index: u8,
    _method_index: u8,
}

#[derive(Decode)]
pub struct CallArgs {
    pub addr_to: MultiAddress,
    pub amount: UIntCompact,
}

pub struct MultiAddress {
    pub is_id: bool,
    pub as_id: [u8; 32],
    pub is_index: bool,
    pub as_index: u32,
    pub is_raw: bool,
    pub as_raw: [u8; 32],
    pub is_address32: bool,
    pub as_address32: [u8; 32],
    pub is_address20: bool,
    pub as_address20: [u8; 20],
}

impl MultiAddress {
    pub fn to_vec(&self) -> Vec<u8> {
        if self.is_id {
            return self.as_id.to_vec();
        }
        if self.is_index {
            return self.as_index.to_le_bytes().to_vec();
        }
        if self.is_raw {
            return self.as_raw.to_vec();
        }
        if self.is_address32 {
            return self.as_address32.to_vec();
        }
        self.as_address20.to_vec()
    }
}

impl Decode for MultiAddress {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let mut address = MultiAddress {
            is_id: false,
            as_id: [0; 32],
            is_index: false,
            as_index: 0,
            is_raw: false,
            as_raw: [0; 32],
            is_address32: false,
            as_address32: [0; 32],
            is_address20: false,
            as_address20: [0; 20],
        };
        let t = input.read_byte()?;

        match t {
            1 => {
                address.is_index = true;
                let mut as_index = [0u8; 4];
                let _ = input.read(&mut as_index);
                address.as_index = u32::from_le_bytes(as_index);
                Ok(address)
            }
            2 => {
                address.is_raw = true;
                let _ = input.read(&mut address.as_raw);
                Ok(address)
            }
            3 => {
                address.is_address32 = true;
                let _ = input.read(&mut address.as_address32);
                Ok(address)
            }
            4 => {
                address.is_address20 = true;
                let _ = input.read(&mut address.as_address20);
                Ok(address)
            }
            _ => {
                address.is_id = true;
                let _ = input.read(&mut address.as_id);
                Ok(address)
            }
        }
    }
}

pub type UIntCompact = U256;

impl Decode for UIntCompact {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let b = input.read_byte()?;
        let mode = b & 3;

        match mode {
            1 => {
                let bb = input.read_byte()?;
                let mut r = bb as u64;
                r <<= 6;
                r += (b >> 2) as u64;
                Ok(U256::from_u64(r))
            }
            2 => {
                let mut buf = [0u8; 4];
                let _ = input.read(&mut buf);
                let mut r = u32::from_le_bytes(buf);
                r >>= 2;
                Ok(U256::from_u64((r) as u64))
            }
            3 => {
                let l = b >> 2;
                if l > 63 {
                    todo!()
                }
                let mut buf = vec![0u8; (l + 4) as usize];
                input.read(&mut buf)?;
                Ok(U256::read_data_as_le(buf))
            }
            _ => Ok(U256::from_u64((b >> 2) as u64)),
        }
    }
}

#[derive(Debug)]
pub struct ExtrinsicPayload {
    pub call_index: [u8; 2],
    pub destination: [u8; 32],
    pub value: [u8; 2],
    pub era: [u8; 1],
    pub nonce: u32,
    pub tip: u8,
    pub mode: u8,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub genesis_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub metadata_hash: u8,
}

impl ExtrinsicPayload {
    pub fn from_raw(bytes: Vec<u8>) -> Result<Self, ChainError> {
        let mut input = bytes.as_slice();

        let mut call_index = [0u8; 2];
        call_index.copy_from_slice(&input[0..2]);
        input = &input[2..];

        let mut destination = [0u8; 32];
        destination.copy_from_slice(&input[0..32]);
        input = &input[32..];

        let mut value = [0u8; 2];
        value.copy_from_slice(&input[0..2]);
        input = &input[2..];

        let mut era = [0u8; 1];
        era.copy_from_slice(&input[0..1]);
        input = &input[1..];

        let nonce = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        input = &input[4..];

        let tip = input[0];
        input = &input[1..];

        let mode = input[0];
        input = &input[1..];

        let spec_version = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        input = &input[4..];

        let transaction_version = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        input = &input[4..];

        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&input[0..32]);
        input = &input[32..];

        let mut block_hash = [0u8; 32];

        block_hash.copy_from_slice(&input[0..32]);
        input = &input[32..];

        let metadata_hash = if input.len() > 0 { input[0] } else { 0 };

        Ok(ExtrinsicPayload {
            call_index,
            destination,
            value,
            era,
            nonce,
            tip,
            mode,
            spec_version,
            transaction_version,
            genesis_hash,
            block_hash,
            metadata_hash,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.extend_from_slice(&self.call_index);
        encoded.push(0x00);
        encoded.extend_from_slice(&self.destination);
        encoded.extend_from_slice(&self.value);
        encoded.extend_from_slice(&self.era);
        encoded.extend_from_slice(Compact(self.nonce).encode().as_slice());
        encoded.extend_from_slice(Compact(self.tip).encode().as_slice());
        encoded.push(self.mode);
        encoded.extend_from_slice(&self.spec_version.encode());
        encoded.extend_from_slice(&self.transaction_version.encode());
        encoded.extend_from_slice(&self.genesis_hash);
        encoded.extend_from_slice(&self.block_hash);
        encoded.push(self.metadata_hash);

        encoded
    }
}
