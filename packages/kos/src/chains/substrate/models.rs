use alloc::vec;
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Input};

use crate::crypto::bignum::U256;

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
        return self.as_address20.to_vec();
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
                return Ok(address);
            }
            2 => {
                address.is_raw = true;
                let _ = input.read(&mut address.as_raw);
                return Ok(address);
            }
            3 => {
                address.is_address32 = true;
                let _ = input.read(&mut address.as_address32);
                return Ok(address);
            }
            4 => {
                address.is_address20 = true;
                let _ = input.read(&mut address.as_address20);
                return Ok(address);
            }
            _ => {
                address.is_id = true;
                let _ = input.read(&mut address.as_id);
                return Ok(address);
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
                return Ok(U256::from_u64((r) as u64));
            }
            2 => {
                let mut buf = [0u8; 4];
                let _ = input.read(&mut buf);
                let mut r = u32::from_le_bytes(buf);
                r >>= 2;
                return Ok(U256::from_u64((r) as u64));
            }
            3 => {
                let l = b >> 2;
                if l > 63 {
                    todo!()
                }
                let mut buf = vec![0u8; (l + 4) as usize];
                input.read(&mut buf)?;
                return Ok(U256::read_data_as_le(buf));
            }
            _ => {
                return Ok(U256::from_u64((b >> 2) as u64));
            }
        }
    }
}
