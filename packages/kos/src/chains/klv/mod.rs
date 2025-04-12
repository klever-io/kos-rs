use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::keccak256_digest;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bech32::{u5, Variant};

use crate::chains::util::private_key_from_vec;

const KLEVER_MESSAGE_PREFIX: &str = "\x17Klever Signed Message:\n";

pub const BIP44_PATH: u32 = 690;

pub struct KLV {}

impl KLV {
    pub fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let mut msg = Vec::new();
        msg.extend_from_slice(KLEVER_MESSAGE_PREFIX.as_bytes());
        msg.extend_from_slice(message.len().to_string().as_bytes());
        msg.extend_from_slice(&message);

        keccak256_digest(&msg[..])
    }
}

impl Chain for KLV {
    fn get_id(&self) -> u32 {
        38
    }

    fn get_name(&self) -> &str {
        "Klever"
    }

    fn get_symbol(&self) -> &str {
        "KLV"
    }

    fn get_decimals(&self) -> u32 {
        6
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let result = bip32::derive_ed25519(&seed, path)?;
        Ok(Vec::from(result))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/{}'/0'/0'/{}'", BIP44_PATH, index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk_bytes = private_key_from_vec(&private_key)?;
        let pbk = Ed25519::public_from_private(&pvk_bytes)?;
        pvk_bytes.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let add_encoded = bech32::convert_bits(public_key.as_ref(), 8, 5, true)?;
        let mut addr_u5: Vec<u5> = Vec::new();
        for i in add_encoded {
            addr_u5.push(u5::try_from_u8(i)?);
        }
        let res = bech32::encode("klv", addr_u5, Variant::Bech32)?;
        Ok(res)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let sig = self.sign_raw(private_key, tx.tx_hash.clone())?;

        tx.signature = sig.as_slice().to_vec();
        Ok(tx)
    }

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let prepared_messafe = KLV::prepare_message(message);
        let signature = self.sign_raw(private_key, prepared_messafe.to_vec())?;
        Ok(signature)
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
        ChainType::KLV
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::{String, ToString};

    #[test]
    fn test_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = crate::chains::klv::KLV {}.get_path(0, false);

        let seed = crate::chains::klv::KLV {}
            .mnemonic_to_seed(mnemonic, String::new())
            .unwrap();
        let pvk = crate::chains::klv::KLV {}.derive(seed, path).unwrap();
        assert_eq!(pvk.len(), 32);
        let pbk = crate::chains::klv::KLV {}.get_pbk(pvk).unwrap();
        assert_eq!(pbk.len(), 32);
        let addr = crate::chains::klv::KLV {}.get_address(pbk).unwrap();
        assert_eq!(
            addr,
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        );
    }

    #[test]
    fn test_pvk_32() {
        let pvk = hex::decode("8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d")
            .unwrap();

        let pbk = crate::chains::klv::KLV {}.get_pbk(pvk).unwrap();

        let address = crate::chains::klv::KLV {}.get_address(pbk.clone()).unwrap();
        assert_eq!(
            address,
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        );
        assert_eq!(pbk.len(), 32);
    }

    #[test]
    fn test_pvk_64() {
        let pvk = hex::decode("8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9de41b323a571fd955e09cd41660ff4465c3f44693c87f2faea4a0fc408727c8ea")
            .unwrap();

        let pbk = crate::chains::klv::KLV {}.get_pbk(pvk).unwrap();

        let address = crate::chains::klv::KLV {}.get_address(pbk.clone()).unwrap();
        assert_eq!(
            address,
            "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy"
        );
        assert_eq!(pbk.len(), 32);
    }

    #[test]
    fn test_sign_raw() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string();
        let path = String::from("m/44'/690'/0'/0'/0'");

        let seed = crate::chains::klv::KLV {}
            .mnemonic_to_seed(mnemonic, String::new())
            .unwrap();
        let pvk = crate::chains::klv::KLV {}.derive(seed, path).unwrap();

        let digest =
            hex::decode("0f47f28830f7aa9607a7a462b267003f94b4ef2c5c28ac8763cfc68e8fe10915");
        let signature = crate::chains::klv::KLV {}
            .sign_raw(pvk, digest.unwrap())
            .unwrap();
        assert_eq!(signature.len(), 64)
    }
}
