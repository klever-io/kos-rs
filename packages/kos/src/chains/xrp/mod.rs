use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::custom_b58enc;
use crate::crypto::bip32;
use crate::crypto::hash::{ripemd160_digest, sha256_digest, sha512_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

/// Unsigned single signer transactions prefix <https://xrpl.org/basic-data-types.html#hash-prefixes>
pub const HASH_PREFIX_UNSIGNED_TRANSACTION_SINGLE: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

pub const XRP_ALPHA: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

#[allow(clippy::upper_case_acronyms)]
pub(crate) struct XRP {}

impl XRP {
    pub fn new() -> Self {
        XRP {}
    }
}

impl XRP {
    fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let sha512_hash: [u8; 64] = sha512_digest(&message);

        let mut sha512_half: [u8; 32] = [0; 32];
        sha512_half.copy_from_slice(&sha512_hash[..32]);

        sha512_half
    }

    fn prepare_transaction(message: Vec<u8>) -> [u8; 32] {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&HASH_PREFIX_UNSIGNED_TRANSACTION_SINGLE);
        buffer.extend_from_slice(message.as_ref());

        let sha512_hash: [u8; 64] = sha512_digest(&buffer);

        let mut sha512_half: [u8; 32] = [0; 32];
        sha512_half.copy_from_slice(&sha512_hash[..32]);

        sha512_half
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
        6
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

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let msg_to_sign = XRP::prepare_transaction(tx.raw_data.clone()).to_vec();
        tx.signature = self.sign_raw(private_key, msg_to_sign.clone())?;
        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let prepared_msg: [u8; 32] = XRP::prepare_message(message);
        self.sign_raw(private_key, prepared_msg.to_vec())
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk_bytes = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig = Secp256K1::sign_der(&payload_bytes, &pvk_bytes)?;
        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::XRP
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::base64::simple_base64_decode;
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

    #[test]
    fn test_sig_message() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);
        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();
        let pub_key = xrp.get_pbk(pvk.clone()).unwrap();
        let address = xrp.get_address(pub_key.clone()).unwrap();
        println!("pub key: {}", hex::encode(pub_key));
        println!("address: {}", address);

        let message = "test message".as_bytes().to_vec();
        let signature = xrp.sign_message(pvk, message).unwrap();

        assert_eq!(hex::encode(signature).to_uppercase(), "3045022100E10177E86739A9C38B485B6AA04BF2B9AA00E79189A1132E7172B70F400ED1170220566BD64AA3F01DDE8D99DFFF0523D165E7DD2B9891ABDA1944E2F3A52CCCB83A");
    }

    #[test]
    fn test_sig_transaction() {
        let xrp = super::XRP::new();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = xrp.get_path(0, false);
        let seed = xrp.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = xrp.derive(seed, path).unwrap();

        let raw_tx = simple_base64_decode("EgAAJAOJPiQuAAAE0mFAAAAAAAAAAWhAAAAAAAAACoEUT3VxzuEHlw82sSKFzBfkTBIcoK6DFIkT5tGhrFdnm0ML+ClCV9S7P1/f").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let tx_signed = xrp.sign_tx(pvk, tx).unwrap();

        assert_eq!(hex::encode(tx_signed.raw_data.clone()).to_uppercase(), "1200002403893E242E000004D261400000000000000168400000000000000A7321031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE74463044022051CA6A9AB7EB0F9994A9B6A838CA49EE7AEEF2B776098A6DD8C7CEA6BF6CB6870220294FFF13FCC7F1ABC24410711243C2084FFC3FC05952B541EA4F759D7A69713881144F7571CEE107970F36B12285CC17E44C121CA0AE83148913E6D1A1AC57679B430BF8294257D4BB3F5FDF");

        assert_eq!(hex::encode(tx_signed.signature).to_uppercase(), "3044022051CA6A9AB7EB0F9994A9B6A838CA49EE7AEEF2B776098A6DD8C7CEA6BF6CB6870220294FFF13FCC7F1ABC24410711243C2084FFC3FC05952B541EA4F759D7A697138");
    }
}
