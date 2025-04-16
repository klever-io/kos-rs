use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo};
use crate::crypto::hash::keccak256_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::crypto::{bip32, secp256k1};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(not(feature = "ksafe"))]
use alloy_dyn_abi::TypedData;

pub(crate) const ETH_ADDR_SIZE: usize = 20;
const ETH_MESSAGE_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";

#[allow(clippy::upper_case_acronyms)]
pub struct ETH {
    pub id: u32,
    pub chaincode: u32,
    pub symbol: String,
    pub name: String,
}

impl Default for ETH {
    fn default() -> Self {
        Self::new()
    }
}

impl ETH {
    pub fn new() -> Self {
        ETH::new_eth_based(3, 1, "ETH", "Ethereum")
    }

    pub fn new_eth_based(id: u32, chaincode: u32, symbol: &str, name: &str) -> Self {
        ETH {
            id,
            chaincode,
            symbol: symbol.to_string(),
            name: name.to_string(),
        }
    }

    pub(crate) fn addr_bytes_to_string(
        address_bytes: [u8; ETH_ADDR_SIZE],
    ) -> Result<String, ChainError> {
        let addr_str = hex::encode(address_bytes);

        let address_hash = hex::encode(keccak256_digest(addr_str.as_bytes()));

        let address = addr_str.as_str();
        let address =
            address
                .char_indices()
                .fold(String::from("0x"), |mut acc, (index, address_char)| {
                    // this cannot fail since it's Keccak256 hashed
                    let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

                    if n > 7 {
                        // make char uppercase if ith character is 9..f
                        acc.push_str(&address_char.to_uppercase().to_string())
                    } else {
                        // already lowercased
                        acc.push(address_char)
                    }

                    acc
                });
        Ok(address.to_string())
    }
}

impl Chain for ETH {
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
        18
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(Vec::from(pvk))
    }

    fn get_path(&self, index: u32, _is_legacy: bool) -> String {
        format!("m/44'/60'/0'/0/{}", index)
    }

    fn get_pbk(&self, private_key: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let mut pvk = private_key_from_vec(&private_key)?;
        let pbk = Secp256K1::private_to_public_uncompressed(&pvk)?;
        pvk.fill(0);
        Ok(Vec::from(pbk))
    }

    fn get_address(&self, public_key: Vec<u8>) -> Result<String, ChainError> {
        let pbk_hash = keccak256_digest(&public_key[1..]);
        let mut address_bytes: [u8; ETH_ADDR_SIZE] = [0; ETH_ADDR_SIZE];
        address_bytes.copy_from_slice(&pbk_hash[12..]);

        ETH::addr_bytes_to_string(address_bytes)
    }

    fn sign_tx(
        &self,
        private_key: Vec<u8>,
        mut tx: Transaction,
    ) -> Result<Transaction, ChainError> {
        let signature = self.sign_raw(private_key, tx.tx_hash.clone())?;
        if signature.len() != 65 {
            return Err(ChainError::InvalidSignature);
        }
        tx.signature = signature.to_vec();

        Ok(tx)
    }

    fn sign_message(
        &self,
        private_key: Vec<u8>,
        message: Vec<u8>,
        _legacy: bool,
    ) -> Result<Vec<u8>, ChainError> {
        #[cfg(not(feature = "ksafe"))]
        {
            if let Ok(data) = std::str::from_utf8(&message) {
                if let Ok(typed_data) = serde_json::from_str::<TypedData>(data) {
                    let digest = typed_data.eip712_signing_hash().unwrap();
                    let mut sig = self.sign_raw(private_key, digest.to_vec())?;

                    let last_index = sig.len() - 1;
                    sig[last_index] += 27;

                    return Ok(sig);
                }
            }
        }

        let to_sign = [
            ETH_MESSAGE_PREFIX,
            message.len().to_string().as_bytes(),
            &message[..],
        ]
        .concat();
        let hashed = keccak256_digest(&to_sign[..]);
        let mut signature = self.sign_raw(private_key, hashed.to_vec())?;

        let last_index = signature.len() - 1;
        signature[last_index] += 27;

        Ok(signature)
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
        ChainType::ETH
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::ToString;

    #[test]
    fn test_derive() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let eth = super::ETH::new();
        let seed = eth.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = eth.get_path(0, false);
        let pvk = eth.derive(seed, path).unwrap();
        let pbk = eth.get_pbk(pvk).unwrap();
        let addr = eth.get_address(pbk).unwrap();
        assert_eq!(addr, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn test_sign_typed_data() {
        let data = r#"{
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Person": [
                    { "name": "name", "type": "string" },
                    { "name": "wallet", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "Person" },
                    { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents": "Hello, Bob!"
            }
        }"#;

        let eth = super::ETH::new();
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();
        let message = data.as_bytes();

        let signature = eth.sign_message(pvk, message.to_vec(), false).unwrap();
        assert_eq!(signature.len(), 65);
    }

    #[test]
    fn test_sign_message() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();

        let eth = super::ETH::new();
        let seed = eth.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = eth.get_path(0, false);
        let pvk = eth.derive(seed, path).unwrap();

        let message_bytes = "test message".as_bytes().to_vec();

        let signature = eth.sign_message(pvk, message_bytes, true).unwrap();

        assert_eq!(
            hex::encode(signature),
            "960e9bb7f2cdfa4325661e11218c28ab2804b8966d6529b86073886a95142c881a965b3608a573ff035a780039afcbca13be25ee57ac175dd5ca7b82b79948c61c"
        );
    }
}
