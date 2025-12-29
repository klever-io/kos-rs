use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::blake2b_digest;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[allow(clippy::upper_case_acronyms)]
pub struct IOTA {}

impl Chain for IOTA {
    fn get_id(&self) -> u32 {
        69
    }

    fn get_name(&self) -> &str {
        "Iota"
    }

    fn get_symbol(&self) -> &str {
        "IOTA"
    }

    fn get_decimals(&self) -> u32 {
        todo!()
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/74218'/0'/0'/{index}'")
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        if public_key.len() != 32 {
            return Err(ChainError::InvalidPublicKey);
        }
        let checksum = blake2b_digest(&public_key);
        let hex_encode = hex::encode(checksum);
        let mut addr = "0x".to_string();
        addr.push_str(&hex_encode[..64]);
        Ok(addr)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let raw = tx.raw_data.clone();
        let signature = self.sign_message(private_key, raw, false)?;
        tx.signature = signature;
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        let mut intent_message = Vec::new();
        intent_message.append(&mut [0; 3].to_vec());
        intent_message.append(&mut message.clone());

        let check_sum = blake2b_digest(&intent_message);
        let mut pvk_bytes = private_key_from_vec(&private_key)?;

        let mut response = Vec::new();
        if !legacy {
            response.push(0x00);
        }

        let signature = Ed25519::sign(&pvk_bytes, &check_sum)?;
        response.append(&mut signature.clone());

        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        response.append(&mut pbk.clone());

        pvk_bytes.fill(0);
        Ok(response)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let signature = Ed25519::sign(&pvk_bytes, &payload)?;

        pvk_bytes.fill(0);
        Ok(signature)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::IOTA
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use crate::test_utils::get_test_mnemonic;
    use alloc::string::{String, ToString};

    #[test]
    fn test_derive() {
        let mnemonic = get_test_mnemonic();

        let sui = super::IOTA {};
        let seed = sui.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let path = sui.get_path(0, false);
        let pvk = sui.derive(seed.clone(), path).unwrap();
        let pbk = sui.get_pbk(pvk.clone()).unwrap();
        let addr = sui.get_address(pbk.clone()).unwrap();
        assert_eq!(
            addr,
            "0x6bc69446b8ff53ec55a8b687cc535533f76631e3ac56dee5cad35c7578967534"
        );
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = get_test_mnemonic();

        let chain = super::IOTA {};
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = chain.sign_message(pvk, message_bytes, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "3e3a6f65ea7764edd49c25693f0dabf49ff3e53de374705d6a78b2495a502d5ea99147f88aed8b00b91490c49cf33581434bc7ea7cee67f6c35a206e44a5df064fc5e0ba2cb70f35c207f53e47345d954255b8f420e0180752b55630caaedd50"
        );
    }
}
