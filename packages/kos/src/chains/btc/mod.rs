mod models;

use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::bip32;
use crate::crypto::hash::{ripemd160_digest, sha256_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use bech32::{u5, Variant};

const BITCOIN_MESSAGE_PREFIX: &str = "\x18Bitcoin Signed Message:\n";

#[allow(clippy::upper_case_acronyms)]
pub struct BTC {
    pub id: u32,
    pub addr_prefix: String,
    pub symbol: String,
    pub name: String,
    pub use_legacy_address: bool,
    pub legacy_version: u8,
}

impl BTC {
    pub fn new() -> Self {
        BTC::new_btc_based(2, "bc", "BTC", "Bitcoin")
    }

    pub fn new_btc_based(id: u32, addr_prefix: &str, symbol: &str, name: &str) -> Self {
        BTC {
            id,
            addr_prefix: addr_prefix.to_string(),
            symbol: symbol.to_string(),
            name: name.to_string(),
            use_legacy_address: false,
            legacy_version: 0,
        }
    }

    pub fn new_legacy_btc_based(id: u32, legacy_version: u8, symbol: &str, name: &str) -> Self {
        BTC {
            id,
            addr_prefix: "".to_string(),
            symbol: symbol.to_string(),
            name: name.to_string(),
            use_legacy_address: true,
            legacy_version,
        }
    }
}

impl BTC {
    fn get_addr_new(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);
        let addr_bytes = hash.to_vec();
        let addr_converted = bech32::convert_bits(&addr_bytes, 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::from([u5::try_from_u8(0).unwrap(); 1]);
        for i in addr_converted {
            addr_u5.push(u5::try_from_u8(i)?);
        }

        let res = bech32::encode(self.addr_prefix.as_str(), addr_u5, Variant::Bech32)?;
        Ok(res)
    }

    pub fn get_addr_legacy(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 33 {
            return Err(ChainError::InvalidPublicKey);
        }

        let mut pubkey_bytes = [0; 33];
        pubkey_bytes.copy_from_slice(&public_key[..33]);

        let hash = ripemd160_digest(&pubkey_bytes);

        let to_base_58 = [vec![self.legacy_version], hash[..].to_vec()].concat();
        let checksum = sha256_digest(&sha256_digest(&to_base_58));
        let checksum_bytes = checksum[..4].to_vec();
        let to_base_58 = [&to_base_58[..], &checksum_bytes[..]].concat();

        let res = b58enc(&to_base_58);
        let addr = String::from_utf8(res)?;
        Ok(addr)
    }

    pub fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let mut msg = Vec::new();
        msg.extend_from_slice(BITCOIN_MESSAGE_PREFIX.as_bytes());
        msg.extend_from_slice(message.len().to_string().as_bytes());
        msg.extend_from_slice(&message);

        sha256_digest(&msg[..])
    }
}

impl Chain for BTC {
    fn get_id(&self) -> u32 {
        self.id
    }
    fn get_name(&self) -> &str {
        self.name.as_str()
    }

    fn get_symbol(&self) -> &str {
        self.symbol.as_str()
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
        format!("m/84'/0'/0'/0/{}", index)
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

    #[allow(clippy::needless_question_mark)]
    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if self.use_legacy_address {
            return Ok(self.get_addr_legacy(public_key)?);
        }

        Ok(self.get_addr_new(public_key)?)
    }

    fn sign_tx(&self, private_key: Vec<u8>, tx: Transaction) -> Result<Transaction, ChainError> {
        let mut tx = tx;

        let mut btc_tx = models::BTCTransaction::from_raw(&tx.raw_data.clone())?;
        btc_tx.sign(&private_key)?;

        tx.raw_data = btc_tx.serialize();

        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let prepared_message = BTC::prepare_message(message);
        let signature = self.sign_raw(private_key, prepared_message.to_vec())?;
        Ok(signature)
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
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let expected =
            hex::decode("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3")
                .unwrap();
        let btc = BTC::new();
        let path = btc.get_path(0, false);
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let res = btc.derive(seed, path).unwrap();
        assert_eq!(res, expected);
    }

    #[test]
    fn test_get_addr() {
        let pvk = hex::decode("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3")
            .unwrap();

        let btc = BTC::new();
        let pbk = btc.get_pbk(pvk).unwrap();
        let addr = btc.get_address(pbk).unwrap();
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn test_get_addr_legacy() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = "m/44'/3'/0'/0/0".to_string();

        let btc = BTC::new_legacy_btc_based(12, 0x1e, "DOGE", "Dogecoin");
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = btc.derive(seed, path).unwrap();
        let pbk = btc.get_pbk(pvk).unwrap();
        let addr = btc.get_address(pbk).unwrap();
        assert_eq!(addr, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = "m/44'/0'/0'/0/0".to_string();

        let btc = BTC::new();
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = btc.derive(seed, path).unwrap();
        let message = "Hello, World!".as_bytes().to_vec();
        let signature = btc.sign_message(pvk, message).unwrap();
        assert_eq!(hex::encode(signature.clone()), "9d561a0ba6ea562e61606e7f3b6a92c889246eec2c05e86e3f465f43469ae9436d7e46accdcfaea848460e42c83c52238b6956c4bfb192e67023b6024e95bdcf01");
        assert_eq!(signature.len(), 65);
    }

    #[test]
    fn decoded_and_sign_transaction() {
        let raw = hex::decode("0100000001a3727243402a869948ccf6d1b61e9b7eabacaa1c1301fcef743bc59ba14664340100000000ffffffff021027000000000000225120236c88c2ba0bdaa1506c42168453629e33a7dbb203e310b069bb22bf67350d2c91c7470000000000160014dc6bf86354105de2fcd9868a2b0376d6731cb92f000000000100000001a3727243402a869948ccf6d1b61e9b7eabacaa1c1301fcef743bc59ba14664340100000000ffffffff021027000000000000225120236c88c2ba0bdaa1506c42168453629e33a7dbb203e310b069bb22bf67350d2c91c7470000000000160014dc6bf86354105de2fcd9868a2b0376d6731cb92f00000000").unwrap();

        let pvk = hex::decode("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3")
            .unwrap();
        let btc = BTC::new();
        let transaction = Transaction {
            raw_data: raw,
            signature: vec![],
            tx_hash: vec![],
        };

        let signed_tx = btc.sign_tx(pvk, transaction).unwrap();
        assert_eq!(signed_tx.raw_data.len(), 192);
    }
}
