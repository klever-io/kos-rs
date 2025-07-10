mod address;

use crate::chains::ada::address::{Address, AddressType, StakeCredential};
use crate::chains::util::private_key_from_vec;
use crate::chains::{util, Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32::{derive_ed25519_bip32, mnemonic_to_seed_ed25519_bip32};
use crate::crypto::ed25519;
use crate::crypto::ed25519::Ed25519Trait;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const BASE_ID: u32 = 20;

pub struct ADA {}

impl ADA {
    pub fn new() -> Self {
        ADA {}
    }
}

impl Default for ADA {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain for ADA {
    fn get_id(&self) -> u32 {
        BASE_ID
    }

    fn get_name(&self) -> &str {
        "Cardano"
    }

    fn get_symbol(&self) -> &str {
        "ADA"
    }

    fn get_decimals(&self) -> u32 {
        6
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
        format!("m/1852'/1815'/0'/0/{index}")
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
            64 | 32 => {
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
        let sig = self.sign_raw(private_key, tx.tx_hash.clone())?;

        tx.signature = sig;
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        let sig = self.sign_raw(private_key.clone(), message)?;

        let pbk = self.get_pbk(private_key)?;

        // public key is not recoverable from signature. So append it to the signature
        let mut sig_with_pbk = Vec::new();

        sig_with_pbk.append(&mut sig.to_vec());
        sig_with_pbk.append(&mut pbk.to_vec());

        Ok(sig_with_pbk)
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
    use crate::chains::Chain;
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
    fn test_sign_message() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string();
        let ada = super::ADA {};

        let seed = ada.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = ada.get_path(0, false);

        let pvk = ada.derive(seed, path).unwrap();
        let message = "test message".as_bytes().to_vec();

        let sig = ada.sign_message(pvk, message, false).unwrap();

        assert_eq!(hex::encode(sig), "3a958c70d7e86c7beae52eba5e0738ee4ede4f27bb2ce79b8082373cb9ac16ea3988a1500b6cc47cde5769d7f7fee886c998ab5e5ea4646024682fadb1adb3057ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a88848e8af62a27a57e982215741c9eac17e6e45cbfd6ea65a0e0dcc03bb777b2".to_string())
    }
}
