use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::Chain;
use crate::chains::{ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::bip32;
use crate::crypto::hash::{ripemd160_digest, sha256_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use bech32::{u5, Variant};

pub const ID: u32 = 2;

const BITCOIN_MESSAGE_PREFIX: &str = "\x18Bitcoin Signed Message:\n";

#[allow(clippy::upper_case_acronyms)]
pub struct BTC {
    pub id: u32,
    pub addr_prefix: String,
    pub bip44: u32,
    pub symbol: String,
    pub name: String,
    pub use_legacy_address: bool,
    pub legacy_version: u8,
}

impl Default for BTC {
    fn default() -> Self {
        Self::new()
    }
}

impl BTC {
    pub fn new() -> Self {
        BTC::new_btc_based(ID, "bc", 0, "BTC", "Bitcoin")
    }

    pub fn new_btc_based(id: u32, addr_prefix: &str, bip44: u32, symbol: &str, name: &str) -> Self {
        BTC {
            id,
            addr_prefix: addr_prefix.to_string(),
            bip44,
            symbol: symbol.to_string(),
            name: name.to_string(),
            use_legacy_address: false,
            legacy_version: 0,
        }
    }

    pub fn new_legacy_btc_based(
        id: u32,
        legacy_version: u8,
        bip44: u32,
        symbol: &str,
        name: &str,
    ) -> Self {
        BTC {
            id,
            addr_prefix: "".to_string(),
            bip44,
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

    pub fn prepare_message_legacy(message: Vec<u8>) -> [u8; 32] {
        sha256_digest(&sha256_digest(&message))
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
        let purpose = if self.use_legacy_address { 44 } else { 84 };

        format!("m/{}'/{}'/0'/0/{}", purpose, self.bip44, index)
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

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        if tx.tx_hash.is_empty() {
            return Err(ChainError::InvalidTransaction(
                "Transaction hash is empty".to_string(),
            ));
        }
        let pvk_bytes = private_key_from_vec(&private_key)?;

        let mut signatures = Vec::new();

        // Each hash in the transaction is 32 bytes long
        for hash in tx.tx_hash.chunks(32) {
            if hash.len() != 32 {
                return Err(ChainError::InvalidTransaction(
                    "Invalid hash length".to_string(),
                ));
            }

            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(hash);

            // Sign hash
            let sig = Secp256K1::sign(&hash_array, &pvk_bytes)?;

            // The first 64 bytes are the signature, and the last byte is the recovery id
            // We just need the first 64 bytes

            signatures.extend_from_slice(&sig[0..64]);
        }

        tx.signature = signatures;

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        if legacy {
            let prepared_message = BTC::prepare_message_legacy(message);
            let signature = self.sign_raw(private_key, prepared_message.to_vec())?;

            // <(byte of 27+public key solution)+4 if compressed >< padded bytes for signature R><padded bytes for signature S>
            let mut sig_vec = Vec::new();
            let rec_byte = signature[64];
            sig_vec.extend_from_slice(&[27 + rec_byte]);
            sig_vec.extend_from_slice(&signature[..64]);

            return Ok(sig_vec);
        }

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

    fn get_chain_type(&self) -> ChainType {
        ChainType::BTC
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
    fn test_get_addr_btc() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let btc = BTC::new();
        let path = btc.get_path(0, true);
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = btc.derive(seed, path).unwrap();
        let pbk = btc.get_pbk(pvk).unwrap();
        let addr = btc.get_address(pbk).unwrap();
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
    #[test]
    fn test_get_addr_doge() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let doge = BTC::new_legacy_btc_based(12, 0x1E, 3, "DOGE", "Dogecoin");
        let path = doge.get_path(0, true);
        let seed = doge.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = doge.derive(seed, path).unwrap();
        let pbk = doge.get_pbk(pvk).unwrap();
        let addr = doge.get_address(pbk).unwrap();
        assert_eq!(addr, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
    }

    #[test]
    fn test_get_addr_ltc() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let ltc = BTC::new_btc_based(5, "ltc", 2, "LTC", "Litecoin");
        let path = ltc.get_path(0, true);
        let seed = ltc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = ltc.derive(seed, path).unwrap();
        let pbk = ltc.get_pbk(pvk).unwrap();
        let addr = ltc.get_address(pbk).unwrap();
        assert_eq!(addr, "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh");
    }
    #[test]
    fn test_get_addr_dash() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let dash = BTC::new_legacy_btc_based(11, 0x4C, 5, "DASH", "Dash");
        let path = dash.get_path(0, true);
        let seed = dash.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = dash.derive(seed, path).unwrap();
        let pbk = dash.get_pbk(pvk).unwrap();
        let addr = dash.get_address(pbk).unwrap();
        assert_eq!(addr, "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5");
    }
    #[test]
    fn test_get_addr_dgb() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let dgb = BTC::new_btc_based(16, "dgb", 20, "DGB", "Digibyte");
        let path = dgb.get_path(0, true);
        let seed = dgb.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = dgb.derive(seed, path).unwrap();
        let pbk = dgb.get_pbk(pvk).unwrap();
        let addr = dgb.get_address(pbk).unwrap();
        assert_eq!(addr, "dgb1q9gmf0pv8jdymcly6lz6fl7lf6mhslsd72e2jq8");
    }
    #[test]
    fn test_get_addr_sys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let sys = BTC::new_btc_based(15, "sys", 57, "SYS", "Syscoin");
        let path = sys.get_path(0, true);
        let seed = sys.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = sys.derive(seed, path).unwrap();
        let pbk = sys.get_pbk(pvk).unwrap();
        let addr = sys.get_address(pbk).unwrap();
        assert_eq!(addr, "sys1q2fs58xaj4tp7qrr3slpdsm65j3nw030d246lmx");
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = "m/44'/0'/0'/0/0".to_string();

        let btc = BTC::new();
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let pvk = btc.derive(seed, path).unwrap();
        let message = "Hello, World!".as_bytes().to_vec();
        let signature = btc.sign_message(pvk, message, false).unwrap();
        assert_eq!(hex::encode(signature.clone()), "9d561a0ba6ea562e61606e7f3b6a92c889246eec2c05e86e3f465f43469ae9436d7e46accdcfaea848460e42c83c52238b6956c4bfb192e67023b6024e95bdcf01");
        assert_eq!(signature.len(), 65);
    }
}
