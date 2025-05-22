use crate::chains::util::private_key_from_vec;
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::hash::blake2b_64_digest;
use crate::crypto::sr25519::Sr25519Trait;
use crate::crypto::{b58, bip32, sr25519};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const LOWER_MASK: u16 = 0x3FFF;
const TYPE1_ACCOUNT_ID: u16 = 63;
const IDENTIFIER_LOWER_MASK: u16 = 0x00FC;
const IDENTIFIER_UPPER_MASK: u16 = 0x0003;
const IDENTIFIER_LOWER_PREFIX: u8 = 0x40;
const SUBSTRATE_NETWORK_PREFIX: &str = "SS58PRE";

pub struct Substrate {
    id: u32,
    network_id: u16,
    name: String,
    symbol: String,
}

impl Substrate {
    pub fn new(id: u32, network_id: u16, name: &str, symbol: &str) -> Self {
        Self {
            id,
            network_id,
            name: name.to_string(),
            symbol: symbol.to_string(),
        }
    }
}

impl Chain for Substrate {
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
        12
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed_substrate(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive_sr25519(&seed, path)?;
        Ok(pvk.to_vec())
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        if index > 0 {
            format!("//{}///", index - 1)
        } else {
            String::new()
        }
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = sr25519::Sr25519::public_from_private(&pvk)?;
        pvk.fill(0);
        Ok(pbk)
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let identifier = self.network_id & LOWER_MASK;
        let mut prefix = Vec::new();
        if identifier < TYPE1_ACCOUNT_ID {
            prefix.push(identifier as u8);
        } else {
            let lower_byte = ((identifier & IDENTIFIER_LOWER_MASK) >> 2) as u8;
            let upper_byte =
                ((identifier >> 8) | ((identifier & IDENTIFIER_UPPER_MASK) << 6)) as u8;
            prefix.push(lower_byte | IDENTIFIER_LOWER_PREFIX);
            prefix.push(upper_byte);
        }

        let data_to_hash = [
            SUBSTRATE_NETWORK_PREFIX.as_bytes(),
            &prefix[..],
            &public_key[..],
        ]
        .concat();
        let digest = blake2b_64_digest(&data_to_hash);

        let to_base_58 = [&prefix[..], &public_key[..], &digest[..2]].concat();
        let encoded = b58::b58enc(&to_base_58);
        let addr = String::from_utf8(encoded).unwrap();
        Ok(addr)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        tx.signature = self.sign_raw(private_key.clone(), tx.tx_hash.clone())?;
        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        self.sign_raw(private_key, message)
    }

    fn sign_raw(&self, private_key: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut private_key_bytes = private_key_from_vec(&private_key)?;
        let sig = sr25519::Sr25519::sign(&payload, &private_key_bytes)?;
        private_key_bytes.fill(0);
        Ok(sig)
    }

    fn get_tx_info(&self, _raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        Err(ChainError::NotSupported)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::SUBSTRATE
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::{String, ToString};
    use schnorrkel;

    #[test]
    fn test_get_addr_1() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(0, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo");
    }
    #[test]
    fn test_get_addr_2() {
        let dot = super::Substrate::new(62, 42, "AVAIL", "Avail");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "5DvaFrBesD6jTWd3GEefcM72BSXaFRHqQuZtwBSZii1VMnuP");
    }
    #[test]
    fn test_get_addr_3() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = dot.get_path(1, false);

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk).unwrap();
        let addr = dot.get_address(pbk).unwrap();
        assert_eq!(addr, "12rsQBSiizNCu3dZDshfkVwB34XDwiqyVQJP6URvGo31YGdp");
    }

    #[test]
    fn test_sign_raw() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let path = String::from("");

        let seed = dot.mnemonic_to_seed(mnemonic, String::from("")).unwrap();
        let pvk = dot.derive(seed, path).unwrap();
        let payload = [0; 32].to_vec();
        let sig = dot.sign_raw(pvk, payload).unwrap();

        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_sign_message() {
        let dot = super::Substrate::new(21, 0, "Polkadot", "DOT");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let seed = dot.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = dot.get_path(0, false);
        let pvk = dot.derive(seed, path).unwrap();
        let pbk = dot.get_pbk(pvk.clone()).unwrap();

        let message = "test message".as_bytes().to_vec();
        let result = dot
            .sign_message(pvk.clone(), message.clone(), false)
            .unwrap();

        let secret_key = schnorrkel::SecretKey::from_bytes(&pvk).unwrap();
        let public_key = schnorrkel::PublicKey::from_bytes(&pbk).unwrap();

        let key_pair = schnorrkel::Keypair {
            secret: secret_key,
            public: public_key,
        };

        let signature = schnorrkel::Signature::from_bytes(&result).unwrap();

        let substrate_ctx: &[u8; 9] = b"substrate";

        let verify_result = key_pair
            .verify_simple(substrate_ctx, &message, &signature)
            .unwrap();

        assert_eq!(true, verify_result == ());
    }
}
