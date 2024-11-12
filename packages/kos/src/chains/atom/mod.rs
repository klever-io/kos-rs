use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::hash::ripemd160_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::crypto::{bip32, secp256k1};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bech32::{u5, Variant};

pub(crate) struct ATOM {
    pub addr_prefix: String,
    #[allow(dead_code)]
    pub network_str: String,
    pub name: String,
    pub symbol: String,
}

impl ATOM {
    pub fn new() -> Self {
        Self {
            addr_prefix: "cosmos".to_string(),
            network_str: "cosmoshub-4".to_string(),
            name: "Cosmos".to_string(),
            symbol: "ATOM".to_string(),
        }
    }

    pub fn new_cosmos_based(
        addr_prefix: &str,
        network_str: &str,
        name: &str,
        symbol: &str,
    ) -> Self {
        Self {
            addr_prefix: addr_prefix.to_string(),
            network_str: network_str.to_string(),
            name: name.to_string(),
            symbol: symbol.to_string(),
        }
    }
}

impl Chain for ATOM {
    fn get_id(&self) -> u32 {
        7
    }

    fn get_name(&self) -> &str {
        self.name.as_str()
    }

    fn get_symbol(&self) -> &str {
        self.symbol.as_str()
    }

    fn get_decimals(&self) -> u32 {
        6
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(Vec::from(pvk))
    }

    fn get_path(&self, index: u32, custom_path: Option<String>) -> String {
        match custom_path {
            Some(path) => path,
            None => format!("m/44'/118'/0'/0/{}", index),
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = Secp256K1::private_to_public_compressed(&pvk)?;
        pvk.fill(0);
        Ok(Vec::from(pbk))
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);
        let addr_bytes = hash.to_vec();
        let add_encoded = bech32::convert_bits(addr_bytes.as_ref(), 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::new();
        for i in add_encoded {
            addr_u5.push(u5::try_from_u8(i)?);
        }
        let res = bech32::encode(self.addr_prefix.as_str(), addr_u5, Variant::Bech32)?;
        Ok(res)
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

        let sig = secp256k1::Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        pvk_bytes.fill(0);
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_addr() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let atom = ATOM::new();
        let seed = atom.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = atom.get_path(0, None);
        let pvk = atom.derive(seed, path).unwrap();
        let pbk = atom.get_pbk(pvk).unwrap();
        let addr = atom.get_address(pbk).unwrap();
        assert_eq!(addr, "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    }
}
