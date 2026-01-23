use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::blake2b_digest;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[allow(clippy::upper_case_acronyms)]
pub struct SUI {
    pub id: u32,
    pub chaincode: u32,
    pub symbol: String,
    pub name: String,
    pub decimals: u32,
    pub use_signed_address: bool,
}

impl Default for SUI {
    fn default() -> Self {
        Self::new()
    }
}

impl SUI {
    pub fn new() -> Self {
        SUI::new_sui_based(51, 784, "SUI", "Sui", 9, true)
    }

    pub fn new_sui_based(
        id: u32,
        chaincode: u32,
        symbol: &str,
        name: &str,
        decimals: u32,
        use_signed_address: bool,
    ) -> Self {
        SUI {
            id,
            chaincode,
            symbol: symbol.to_string(),
            name: name.to_string(),
            decimals,
            use_signed_address,
        }
    }
}

impl Chain for SUI {
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
        self.decimals
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/{}'/0'/0'/{index}'", self.chaincode)
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

        let checksum = if self.use_signed_address {
            // SUI-style: prepend 0 byte to create 33-byte array
            let mut signed_pbk = [0u8; 33];
            signed_pbk[1..].copy_from_slice(&public_key[..]);
            blake2b_digest(&signed_pbk)
        } else {
            // IOTA-style: hash public key directly
            blake2b_digest(&public_key)
        };

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
        ChainType::SUI
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

        let sui = super::SUI::new();
        let seed = sui.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let path = sui.get_path(0, false);
        let pvk = sui.derive(seed.clone(), path).unwrap();
        let pbk = sui.get_pbk(pvk.clone()).unwrap();
        let addr = sui.get_address(pbk.clone()).unwrap();
        assert_eq!(
            addr,
            "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"
        );
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = get_test_mnemonic();

        let chain = super::SUI::new();
        let seed = chain.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = chain.get_path(0, false);
        let pvk = chain.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = chain.sign_message(pvk, message_bytes, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "73b5a37df5ae989ec52a970547fdee96e4e76f0c668159b40a4864f2e06637cac485bfcd3e5af9a29a383243c41549c7c5b2ba645ad68aa849c6b08a53a18b02900b4d81eecea3df2f74b14200c4f4cf3f49afaca7a634ffd2cf6ff82bdaecf2"
        );
    }

    #[test]
    fn test_derive_iota() {
        let mnemonic = get_test_mnemonic();

        let iota = super::SUI::new_sui_based(69, 4218, "IOTA", "Iota", 6, false);
        let seed = iota.mnemonic_to_seed(mnemonic, String::new()).unwrap();
        let path = iota.get_path(0, false);
        let pvk = iota.derive(seed.clone(), path).unwrap();
        let pbk = iota.get_pbk(pvk.clone()).unwrap();
        let addr = iota.get_address(pbk.clone()).unwrap();
        assert_eq!(
            addr,
            "0x365b74f27ca7c6d7ce019d73042f85cc4627e1aeec2b7822994e16010234e576"
        );
    }

    #[test]
    fn test_sign_message_iota() {
        let mnemonic = get_test_mnemonic();

        let iota = super::SUI::new_sui_based(69, 4218, "IOTA", "Iota", 6, false);
        let seed = iota.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = iota.get_path(0, false);
        let pvk = iota.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = iota.sign_message(pvk, message_bytes, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "03d8debef73a53b359ec4426340e0a0bb490c7fd63685c04837a22e384708e1f11f022c8799e6d21a1599e81c5b9963dcbdcc936596c85d2daea51e1687b5e09931c54b678837cf96a49ee1d1122027fabadf0aee97d9f9094187db8be396f63"
        );
    }
}
