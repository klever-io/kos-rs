use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::hash::ripemd160_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const BCH_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BCH_PREFIX: &str = "bitcoincash";
const BCH_MASK: u8 = 0x1f;

pub struct BCH {}

impl BCH {
    fn expand_prefix(prefix: &str) -> Result<Vec<u8>, ChainError> {
        let mut prefix_bytes = prefix.as_bytes().to_vec();
        for i in 0..prefix_bytes.len() {
            prefix_bytes[i] = prefix_bytes[i] & BCH_MASK;
        }

        prefix_bytes.push(0u8);
        Ok(prefix_bytes)
    }

    fn create_checksum(prefix: &str, payload: &[u8]) -> Result<Vec<u8>, ChainError> {
        let expanded_prefix = BCH::expand_prefix(prefix)?;
        let to_encode = [expanded_prefix, payload.to_vec(), vec![0u8; 8]].concat();
        let check = BCH::poly_mod(&to_encode);
        let mut ret = [0u8; 8];
        for i in 0..ret.len() {
            ret[i] = ((check >> (5 * (7 - i))) & (BCH_MASK as u64)) as u8;
        }

        Ok(ret.to_vec())
    }

    fn poly_mod(p_input: &[u8]) -> u64 {
        const POLY_TABLE: [u64; 5] = [
            0x98f2bc8e61,
            0x79b76d99e2,
            0xf33e5fb3c4,
            0xae2eabe2a8,
            0x1e4f43e470,
        ];
        let mut check: u64 = 1;

        for &item in p_input.iter() {
            let check0 = (check >> 35) as u8; // Assuming C0_SHIFT_COUNT is 35, as it's not defined in the original code

            check = ((check & 0x07ffffffff) << 5) ^ (item as u64);

            if (check0 & 0x01) > 0 {
                check ^= POLY_TABLE[0];
            }
            if (check0 & 0x02) > 0 {
                check ^= POLY_TABLE[1];
            }
            if (check0 & 0x04) > 0 {
                check ^= POLY_TABLE[2];
            }
            if (check0 & 0x08) > 0 {
                check ^= POLY_TABLE[3];
            }
            if (check0 & 0x10) > 0 {
                check ^= POLY_TABLE[4];
            }
        }

        check ^ 1
    }
}

impl Chain for BCH {
    fn get_name(&self) -> &str {
        "Bitcoin Cash"
    }

    fn get_symbol(&self) -> &str {
        "BCH"
    }

    fn get_decimals(&self) -> u32 {
        8
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Secp256K1::private_to_public_compressed(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk.to_vec())
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);
        let to_base_58 = [vec![0x00], hash[..].to_vec()].concat();
        let addr_converted = bech32::convert_bits(&to_base_58, 8, 5, true)?;
        let checksum = BCH::create_checksum(BCH_PREFIX, &addr_converted)?;

        let mut final_address = Vec::new();
        for i in 0..addr_converted.len() {
            final_address.push(BCH_CHARSET.as_bytes()[addr_converted[i] as usize]);
        }

        for i in 0..checksum.len() {
            final_address.push(BCH_CHARSET.as_bytes()[checksum[i] as usize]);
        }

        Ok(String::from_utf8(final_address)?)
    }

    fn sign_tx(&self, _private_key: Vec<u8>, _tx: Transaction) -> Result<Transaction, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_message(
        &self,
        _private_key: Vec<u8>,
        _message: Vec<u8>,
    ) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::ToString;

    #[test]
    fn test_bch_address() {
        let bch = super::BCH{};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = bch.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = bch.derive(seed, "m/44'/145'/0'/0/0".to_string()).unwrap();
        let pbk = bch.get_pbk(pvk).unwrap();
        let addr = bch.get_address(pbk).unwrap();

        assert_eq!(addr, "qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6");
    }
}


