use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::b58::b58enc;
use crate::crypto::hash::{keccak256_digest, sha256_digest};
use crate::crypto::secp256k1::Secp256k1Trait;
use crate::crypto::{bip32, secp256k1};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const TRX_ADDR_PREFIX: u8 = 0x41;
const TRX_ADD_RAW_LEN: usize = 21;
const TRX_ADD_SIZE: usize = 25;

pub const BIP44_PATH: u32 = 195;

pub const TRON_MESSAGE_PREFIX: &str = "\x19TRON Signed Message:\n";
pub struct TRX {}

impl TRX {
    pub fn expand_address_with_checksum(address: &[u8; 21]) -> String {
        let mut address_with_checksum: [u8; TRX_ADD_SIZE] = [0; TRX_ADD_SIZE];
        address_with_checksum[..TRX_ADD_RAW_LEN].copy_from_slice(&address[..]);
        let hash = sha256_digest(&address_with_checksum[..TRX_ADD_RAW_LEN]);
        let hash = sha256_digest(&hash[..]);
        address_with_checksum[21..].copy_from_slice(&hash[0..4]);
        let bytes_addr = b58enc(&address_with_checksum[..]);
        String::from_utf8(bytes_addr).unwrap()
    }
}

impl Chain for TRX {
    fn get_id(&self) -> u32 {
        1
    }

    fn get_name(&self) -> &str {
        "TRON"
    }

    fn get_symbol(&self) -> &str {
        "TRX"
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

    fn get_path(&self, index: u32, is_legacy: bool) -> String {
        if is_legacy {
            format!("m/44'/{BIP44_PATH}'/{index}'")
        } else {
            format!("m/44'/{BIP44_PATH}'/0'/0/{index}")
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = secp256k1::Secp256K1::private_to_public_uncompressed(&pvk)?;
        pvk.fill(0);
        Ok(Vec::from(pbk))
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let hash = keccak256_digest(&public_key[1..]);

        let mut address: [u8; TRX_ADD_RAW_LEN] = [0; TRX_ADD_RAW_LEN];
        address[0] = TRX_ADDR_PREFIX;
        address[1..TRX_ADD_RAW_LEN].copy_from_slice(&hash[12..]);
        Ok(TRX::expand_address_with_checksum(&address))
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pvk_bytes: [u8; 32] = [0; 32];
        pvk_bytes.copy_from_slice(&private_key[..32]);

        let mut payload = [0u8; 32];
        payload.copy_from_slice(&tx.tx_hash[..]);

        tx.signature = secp256k1::Secp256K1::sign(&payload, &pvk_bytes)?.to_vec();

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        if private_key.len() != 32 {
            return Err(ChainError::InvalidPrivateKey);
        }

        let mut pvk_bytes: [u8; 32] = [0; 32];
        pvk_bytes.copy_from_slice(&private_key[..32]);

        let sig = self.sign_raw(private_key, message)?;
        Ok(sig.as_slice().to_vec())
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

    fn get_chain_type(&self) -> ChainType {
        ChainType::TRX
    }
}

#[cfg(test)]
mod test {
    use crate::chains::{trx::TRON_MESSAGE_PREFIX, Chain};
    use crate::crypto::hash::keccak256_digest;
    use crate::test_utils::get_test_mnemonic;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    #[test]
    fn test_trx_derive() {
        let mnemonic = get_test_mnemonic();

        let seed = crate::chains::trx::TRX {}
            .mnemonic_to_seed(mnemonic, String::from(""))
            .unwrap();
        let path = crate::chains::trx::TRX {}.get_path(0, false);
        let pvk = crate::chains::trx::TRX {}.derive(seed, path).unwrap();
        assert_eq!(pvk.len(), 32);
        let pbk = crate::chains::trx::TRX {}.get_pbk(pvk).unwrap();
        assert_eq!(pbk.len(), 65);
        let addr = crate::chains::trx::TRX {}.get_address(pbk).unwrap();
        assert_eq!(addr, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = get_test_mnemonic();

        let chain = super::TRX {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let message = "test message".as_bytes().to_vec();

        let mut msg = Vec::new();
        msg.extend_from_slice(TRON_MESSAGE_PREFIX.as_bytes());
        msg.extend_from_slice(message.len().to_string().as_bytes());
        msg.extend_from_slice(&message);

        let message_bytes = keccak256_digest(&msg[..]);

        let signature = chain
            .sign_message(pvk, message_bytes.to_vec(), false)
            .unwrap();

        assert_eq!(
            hex::encode(signature),
            "cf7b64342bc41955671164c8d5fe7ee992e9497ff4bedcad02f7236be994e4821e2e3fe5807f88ff7099ab3ce8973e4399ccb24bcb41c8d92c64675a32c77e7101"
        );
    }
}
