mod address;
mod transaction;

use crate::chains::ada::address::{Address, AddressType, StakeCredential};
use crate::chains::ada::transaction::{RosettaTransaction, Tx, TxBody, VKeyWitness, WitnessSet};
use crate::chains::util::private_key_from_vec;
use crate::chains::{util, Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32::{derive_ed25519_bip32, mnemonic_to_seed_ed25519_bip32};
use crate::crypto::ed25519;
use crate::crypto::ed25519::Ed25519Trait;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct ADA {}

impl Chain for ADA {
    fn get_id(&self) -> u32 {
        20
    }

    fn get_name(&self) -> &str {
        "Cardano"
    }

    fn get_symbol(&self) -> &str {
        "ADA"
    }

    fn get_decimals(&self) -> u32 {
        todo!()
    }

    fn mnemonic_to_seed(&self, mnemonic: String, _password: String) -> Result<Vec<u8>, ChainError> {
        Ok(mnemonic_to_seed_ed25519_bip32(mnemonic)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        if seed.len() != 96 {
            return Err(ChainError::InvalidSeed);
        }

        let mut seed_arr = [0u8; 96];
        seed_arr.copy_from_slice(&seed[..]);

        Ok(derive_ed25519_bip32(seed_arr, path)?.to_vec())
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/1852'/1815'/0'/0/{}", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        match private_key.len() {
            64 => {
                let mut pvk = private_key_from_vec(&private_key)?;
                let pbk = ed25519::Ed25519::public_from_extended(&pvk)?;
                pvk.fill(0);
                if pbk.len() < 32 {
                    return Err(ChainError::InvalidPrivateKey);
                }

                Ok(pbk[0..32].to_vec())
            }
            96 => {
                let mut pvk = [0u8; 64];
                let mut cc = [0u8; 32];
                pvk.copy_from_slice(&private_key[..64]);
                cc.copy_from_slice(&private_key[64..]);
                let vk = self.get_pbk(pvk.to_vec())?;
                let mut xvk = Vec::new();
                xvk.append(&mut vk.to_vec());
                xvk.append(&mut cc.to_vec());

                pvk.fill(0);
                cc.fill(0);

                Ok(xvk)
            }
            _ => Err(ChainError::InvalidPrivateKey),
        }
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        match public_key.len() {
            128 => {
                let pbk = &public_key[..32];
                let pbk_stake = &public_key[32..64];

                let payment = StakeCredential::new(pbk);
                let stake = StakeCredential::new(pbk_stake);
                let address = Address {
                    network: 1,
                    _type: AddressType::Base.to_u8(),
                    payment_cred: Some(payment),
                    stake_cred: Some(stake),
                };

                Ok(address.encode_bech32()?.to_string())
            }
            64 => {
                let payment = StakeCredential::new(&public_key[0..32]);
                let address = Address {
                    network: 1,
                    _type: AddressType::Enterprise.to_u8(),
                    payment_cred: Some(payment),
                    stake_cred: None,
                };

                Ok(address.encode_bech32()?.to_string())
            }
            _ => Err(ChainError::InvalidPublicKey),
        }
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let mut rosetta_tx: RosettaTransaction = minicbor::decode(tx.raw_data.as_slice()).unwrap();

        println!("{:?}", rosetta_tx);

        let metadata = hex::decode(rosetta_tx.metadata).unwrap();

        println!("{:?}", hex::encode(metadata.clone()));

        let tx_body: TxBody = minicbor::decode(metadata.as_slice()).unwrap();

        // Reducing from xprivkey to privkey
        let pvk = if private_key.len() == 96 {
            &private_key[..64]
        } else {
            private_key.as_slice()
        };

        let hash = tx_body.hash()?;

        let pbk = self.get_pbk(pvk.to_vec())?;

        let signature = self.sign_raw(pvk.to_vec(), hash.to_vec())?;

        let witness_set = WitnessSet {
            v_key_witness_set: vec![VKeyWitness {
                v_key: pbk,
                signature: signature.clone(),
            }],
        };

        let cardano_tx = Tx {
            body: Some(tx_body),
            witness_set,
            is_valid: true,
            auxiliary_data: None,
        };

        let mut signed_metadata = Vec::new();

        // Encode signed metadata
        match minicbor::encode(&cardano_tx, &mut signed_metadata)
            .map_err(|e| ChainError::InvalidData(e.to_string()))
        {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        rosetta_tx.metadata = hex::encode(&signed_metadata);

        let new_raw = Vec::new();

        minicbor::encode(&rosetta_tx, new_raw.clone())
            .map_err(|e| ChainError::InvalidData(e.to_string()))?;

        tx.raw_data = new_raw;
        tx.signature = signature;

        Ok(tx)
    }

    fn sign_message(
        &self,
        _private_key: Vec<u8>,
        _message: Vec<u8>,
    ) -> Result<Vec<u8>, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut private_key_bytes = util::private_key_from_vec(&private_key)?;
        let sig = ed25519::Ed25519::sign_extended(&private_key_bytes, &payload)?;
        private_key_bytes.fill(0);
        Ok(sig)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::ADA
    }
}

#[cfg(test)]
mod test {
    use crate::chains::{Chain, Transaction};
    use crate::crypto::base64::simple_base64_decode;
    use alloc::string::ToString;

    #[test]
    fn test_address() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string();
        let ada = super::ADA {};

        let seed = ada.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = ada.get_path(0, false);

        let pvk = ada.derive(seed, path).unwrap();
        let pbk = ada.get_pbk(pvk).unwrap();
        let addr = ada.get_address(pbk).unwrap();
        assert_eq!(
            addr,
            "addr1vy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7ss7lxrqp"
        );
    }

    #[test]
    fn test_sign() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string();
        let ada = super::ADA {};

        let seed = ada.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = ada.get_path(0, false);

        let pvk = ada.derive(seed, path).unwrap();

        let raw_data = simple_base64_decode("gnkBNmE0MDA4MTgyNTgyMGQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzEwMDAxODI4MjU4MzkwMWFmMDZmYTVmMWIyOGM5MGJkYzFjODdiYmI2NzMwYmMwZGE5ODY0MjBjNGJkMDBmZDRlNWRkMWYyYWViMGM3NDdjNjhhNDAzYzJlY2UwNWE3OTg4MWVmZTk0YWVjMmVjOTIyZmU0YmQxYzA4ZTNkNjMxYTAwMGY0MjQwODI1ODFkNjFkNTVmNDUzZjkzOTU0NzU1OTEzOTkxZDIxMTk1MmU0YmRkZmNjZDllZWE3ZTQyNDk2N2E3NzlmNDFhMDEwZjcxYTEwMjFhMDAwMzM2ZGYwMzFhMDhmNzFlOTWham9wZXJhdGlvbnOBpnRvcGVyYXRpb25faWRlbnRpZmllcqFlaW5kZXgAZHR5cGVlaW5wdXRmc3RhdHVzYGdhY2NvdW50oWdhZGRyZXNzeDphZGRyMXY4MjQ3M2ZsancyNXc0djM4eGdheXl2NDllOWFtbHhkbm00OHVzamZ2N25obmFxOXYyNTl1ZmFtb3VudKJldmFsdWVoMTkwMDAwMDBoY3VycmVuY3miZnN5bWJvbGNBREFoZGVjaW1hbHMGa2NvaW5fY2hhbmdlom9jb2luX2lkZW50aWZpZXKhamlkZW50aWZpZXJ4QmQxOWMwNTQwOTlkODllMjJiNWJlNTU3ZTI0YzAyMzE0ZGU3YWM5M2Q3ZDFlNjAyZDNiYmZjODY4NDY3OWQzYzE6MGtjb2luX2FjdGlvbmpjb2luX3NwZW50").unwrap();

        let tx = Transaction {
            raw_data,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let signed_tx = ada.sign_tx(pvk, tx).unwrap();

        println!("{:}", hex::encode(signed_tx.raw_data))
    }
}
