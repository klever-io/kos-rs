use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::b58::custom_b58enc;
use crate::crypto::bip32;
use crate::crypto::hash::{ripemd160_digest, sha256_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

const XRP_ALPHA: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub(crate) struct XRP {}

impl XRP {
    pub fn new() -> Self {
        XRP {}
    }
}

impl Chain for XRP {
    fn get_id(&self) -> u32 {
        4
    }

    fn get_name(&self) -> &str {
        "Ripple"
    }

    fn get_symbol(&self) -> &str {
        "XRP"
    }

    fn get_decimals(&self) -> u32 {
        todo!()
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/144'/0'/0/{}", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pk_bytes: [u8; 32] = [0; 32];
        pk_bytes.copy_from_slice(&private_key[..32]);

        let pbk = Secp256K1::private_to_public_compressed(&pk_bytes)?;
        Ok(pbk.to_vec())
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);

        let to_base_58 = [vec![0], hash[..].to_vec()].concat();
        let checksum = sha256_digest(&sha256_digest(&to_base_58));
        let checksum_bytes = checksum[..4].to_vec();
        let to_base_58 = [&to_base_58[..], &checksum_bytes[..]].concat();

        let res = custom_b58enc(&to_base_58, XRP_ALPHA);
        let addr = String::from_utf8(res)?;
        Ok(addr)
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
        let pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::{String, ToString};

    #[test]
    fn test_get_addr() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);

        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();
        let pbk = xrp.get_pbk(pvk).unwrap();
        let addr = xrp.get_address(pbk).unwrap();

        assert_eq!(addr, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
    }
}
