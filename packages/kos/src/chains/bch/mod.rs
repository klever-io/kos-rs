use crate::chains::btc::BTC;
use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::hash::ripemd160_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};

use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

const BCH_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BCH_PREFIX: &str = "bitcoincash";
const BCH_MASK: u8 = 0x1f;

#[allow(clippy::upper_case_acronyms)]
pub struct BCH {}

impl BCH {
    #[allow(clippy::needless_range_loop)]
    fn expand_prefix(prefix: &str) -> Result<Vec<u8>, ChainError> {
        let mut prefix_bytes = prefix.as_bytes().to_vec();
        for i in 0..prefix_bytes.len() {
            prefix_bytes[i] &= BCH_MASK;
        }

        prefix_bytes.push(0u8);
        Ok(prefix_bytes)
    }

    #[allow(clippy::needless_range_loop)]
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
    fn get_id(&self) -> u32 {
        18
    }
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

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/145'/0'/0/{}", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Secp256K1::private_to_public_compressed(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk.to_vec())
    }

    #[allow(clippy::needless_range_loop)]
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

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let mut sighash_vec: Vec<[u8; 32]> = Vec::new();
        for chunk in tx.signature.chunks(32) {
            let mut array = [0u8; 32];
            array[..chunk.len()].copy_from_slice(chunk);
            sighash_vec.push(array);
        }

        let mut signatures: Vec<Vec<u8>> = Vec::new();
        signatures.push((sighash_vec.len() as u32).to_le_bytes().to_vec());
        for sig_hash in sighash_vec {
            let signature = self.sign_raw(private_key.clone(), sig_hash.to_vec())?;

            let len: usize = signature.len();

            let mut signature_fixed = [0u8; 73]; // 73 max size

            signature_fixed[..len].copy_from_slice(&signature[..len]);
            signature_fixed[len] = 0x41; // 0x01 | 0x40; // 0x41;

            signatures.push(((len + 1) as u32).to_le_bytes().to_vec());
            signatures.push(signature_fixed[..len + 1].to_vec());
        }

        tx.signature = signatures.iter().flat_map(|sig| sig.to_vec()).collect();

        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let btc = BTC::new();
        btc.sign_message(private_key, message)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign_der(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::BCH
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chains::{Chain, ChainOptions};
    use alloc::string::ToString;

    #[test]
    fn test_bch_address() {
        let bch = super::BCH {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = bch.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = bch.get_path(0, false);
        let pvk = bch.derive(seed, path).unwrap();
        let pbk = bch.get_pbk(pvk).unwrap();
        let addr = bch.get_address(pbk).unwrap();

        assert_eq!(addr, "qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6");
    }

    #[test]
    fn test_bch_sign_tx() {
        let bch = super::BCH {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = bch.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = bch.get_path(0, false);
        let pvk = bch.derive(seed, path).unwrap();

        let raw_tx = hex::decode("0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000").unwrap();

        let signature = hex::decode("3bb9d471a2ddecc4e1d77cd7ae442e4f024e80615f7b616c04045362092fe8316b7f20194c402047f01803f8a2c125bb7fab49c764c5d436b1b3443d5c118be4").unwrap();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: signature,
            options: Some(ChainOptions::BTC {
                prev_scripts: vec![
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                ],
                input_amounts: vec![498870, 1001016],
            }),
        };

        let result = bch.sign_tx(pvk, tx).unwrap();

        assert_eq!(hex::encode(result.signature), "0200000048000000304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a414700000030440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d41");
    }

    #[test]
    fn test_bch_sign_message() {
        let bch = super::BCH {};
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let seed = bch.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = bch.get_path(0, false);
        let pvk = bch.derive(seed, path).unwrap();

        let result = bch
            .sign_message(pvk, "test message".as_bytes().to_vec())
            .unwrap();

        assert_eq!(hex::encode(result), "303a181697a1b5d5b4f5adac6f42a44a660c893589c4b52ef71385ccc301a4d27b6c9068e30b84e5f3d08ca314cd45563c3114b4f42216945de1304f85e0617b00");
    }
}
