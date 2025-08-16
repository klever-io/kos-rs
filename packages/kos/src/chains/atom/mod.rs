use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::hash::{ripemd160_digest, sha256_digest};
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::crypto::{bip32, secp256k1};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bech32::{u5, Variant};

#[allow(clippy::upper_case_acronyms)]
pub(crate) struct ATOM {
    pub id: u32,
    pub addr_prefix: String,
    #[allow(dead_code)]
    pub network_str: String,
    pub name: String,
    pub symbol: String,
}

impl ATOM {
    fn prepare_message(message: Vec<u8>) -> [u8; 32] {
        let sha256_hash = sha256_digest(sha256_digest(message.as_ref()).as_ref());
        sha256_hash
    }

    fn prepare_transaction(message: Vec<u8>) -> [u8; 32] {
        let sha256_hash = sha256_digest(message.as_ref());
        sha256_hash
    }
}

impl ATOM {
    pub fn new() -> Self {
        Self {
            id: 7,
            addr_prefix: "cosmos".to_string(),
            network_str: "cosmoshub-4".to_string(),
            name: "Cosmos".to_string(),
            symbol: "ATOM".to_string(),
        }
    }

    pub fn new_cosmos_based(
        id: u32,
        addr_prefix: &str,
        network_str: &str,
        name: &str,
        symbol: &str,
    ) -> Self {
        Self {
            id,
            addr_prefix: addr_prefix.to_string(),
            network_str: network_str.to_string(),
            name: name.to_string(),
            symbol: symbol.to_string(),
        }
    }
}

impl Chain for ATOM {
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
        6
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(Vec::from(pvk))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/118'/0'/0/{index}")
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

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let prepared_tx = ATOM::prepare_transaction(tx.raw_data.clone()).to_vec();
        let signature = self.sign_raw(private_key, prepared_tx)?;

        tx.signature = signature[..64].to_vec();

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        let prepared_msg: [u8; 32] = ATOM::prepare_message(message);
        let signature = self.sign_raw(private_key, prepared_msg.to_vec())?;

        // <(byte of 27+public key solution)+4 if compressed >< padded bytes for signature R><padded bytes for signature S>
        let mut sig_vec = Vec::new();
        let rec_byte = signature[64];
        sig_vec.extend_from_slice(&[27 + rec_byte]);
        sig_vec.extend_from_slice(&signature[..64]);

        Ok(sig_vec.to_vec())
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let pvk_bytes: [u8; 32] = private_key_from_vec(&private_key)?;
        let payload_bytes = slice_from_vec(&payload)?;

        let sig: [u8; 65] = secp256k1::Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

        Ok(sig.to_vec())
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::ATOM
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_test_mnemonic;
    use alloc::vec;

    #[test]
    fn test_get_addr() {
        let mnemonic = get_test_mnemonic().to_string();

        let atom = ATOM::new();
        let seed = atom.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = atom.get_path(0, false);
        let pvk = atom.derive(seed, path).unwrap();
        let pbk = atom.get_pbk(pvk.clone()).unwrap();
        let addr = atom.get_address(pbk.clone()).unwrap();

        assert_eq!(addr, "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    }

    #[test]
    fn test_sign_message() {
        let mnemonic = get_test_mnemonic().to_string();

        let atom = ATOM::new();
        let seed = atom.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = atom.get_path(0, false);
        let pvk = atom.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = atom.sign_message(pvk, message_bytes, false).unwrap();

        assert_eq!(
            hex::encode(signature),
            "1cd48bf6446d3cd53869ff9ab787548fd04648fe4a1bc72cab594f9cd9a525d88e6a1b0c6252247f11dd8361629635df0e98f2ceedfee06bb6a116d18f5c5da150"
        );
    }

    #[test]
    fn test_sign_transaction() {
        let mnemonic = get_test_mnemonic().to_string();

        let atom = ATOM::new();
        let seed = atom.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = atom.get_path(0, false);
        let pvk = atom.derive(seed, path).unwrap();

        let raw_tx = hex::decode("0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180f12130a0d0a057561746f6d12043235303010a7e5061a0b636f736d6f736875622d3420b1ef78").unwrap();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: Option::None,
        };

        let tx_signed = atom.sign_tx(pvk, tx).unwrap();

        assert_eq!(
            hex::encode(tx_signed.raw_data.clone()),
            "0a91010a8a010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126a0a2d636f736d6f733173706b326e686a6d67706d37713767796d753839727a37636c686e34787578756e6c37737879122d636f736d6f733130377871366b787036353471666832643872687171736d36793364656a7237397639746d37341a0a0a057561746f6d12013112024f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180f12130a0d0a057561746f6d12043235303010a7e5061a0b636f736d6f736875622d3420b1ef78"
        );

        assert_eq!(
            hex::encode(tx_signed.signature.clone()),
            "48e55515c0edc40f80a976f2ce79683ec179e2b8b31e2f5d55cef448aa352ea256919f479254e889a507fcb98a5768b7e9a55358516e199a93e58130278918b1"
        );
    }
}
