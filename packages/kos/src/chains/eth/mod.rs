mod models;

use crate::chains::eth::models::EthereumTransaction;
use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, ChainType, Transaction, TxInfo, TxType};
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
        let mut eth_tx = EthereumTransaction::decode(&tx.raw_data)?;

        //Ensure empty signature
        eth_tx.signature = None;
        if eth_tx.transaction_type == models::TransactionType::Legacy {
            eth_tx.chain_id = Some(self.chaincode as u64);
        }

        let new_rlp = eth_tx.encode()?;
        let to_sign = keccak256_digest(&new_rlp[..]);
        let signature = self.sign_raw(private_key, to_sign.to_vec())?;
        if signature.len() != 65 {
            return Err(ChainError::InvalidSignature);
        }

        let _sig_hex = hex::encode(&signature[..]);

        let mut signature_bytes: [u8; 65] = [0; 65];
        signature_bytes.copy_from_slice(&signature[..]);
        eth_tx.signature = Some(signature_bytes);
        let signed_rlp = eth_tx.encode()?;
        tx.raw_data = signed_rlp.clone();
        tx.tx_hash = Vec::from(keccak256_digest(&signed_rlp[..]));
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

    fn get_tx_info(&self, raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        let eth_tx = EthereumTransaction::decode(raw_tx.as_slice())?;
        let mut tx_info = TxInfo {
            sender: String::new(),
            receiver: String::new(),
            value: 0.0,
            tx_type: TxType::Transfer,
        };

        if eth_tx.to.is_some() {
            tx_info.tx_type = TxType::TriggerContract;
            let addr_vec = eth_tx.to.unwrap_or([0; ETH_ADDR_SIZE].to_vec());
            let mut address_bytes: [u8; ETH_ADDR_SIZE] = [0; ETH_ADDR_SIZE];
            address_bytes.copy_from_slice(&addr_vec[..]);
            tx_info.receiver = ETH::addr_bytes_to_string(address_bytes)?;
        }

        tx_info.value = eth_tx.value.to_f64(self.get_decimals());

        Ok(tx_info)
    }

    fn get_chain_type(&self) -> ChainType {
        ChainType::ETH
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::ToString;
    use alloc::vec::Vec;

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
    fn test_sign_tx() {
        let raw_tx = hex::decode(
            "b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080",
        )
        .unwrap();
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();
        let eth = super::ETH::new();

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let _ = eth.sign_tx(pvk, tx).unwrap();
    }

    #[test]
    fn test_sign_london_tx() {
        let raw_tx = hex::decode("b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080").unwrap();
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();
        let eth = super::ETH::new_eth_based(3, 56, "ETH", "Ethereum");

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let _ = eth.sign_tx(pvk, tx).unwrap();
    }

    #[test]
    fn test_decode_tx() {
        let raw_tx = hex::decode(
            "ad02eb01038493a7d5d085068da15595825208944cbeee256240c92a9ad920ea6f4d7df6466d2cdc0a80c0808080",
        )
        .unwrap();
        let eth = super::ETH::new();
        let tx_info = eth.get_tx_info(raw_tx).unwrap();
        assert_eq!(
            tx_info.receiver,
            "0x4cBeee256240c92A9ad920ea6f4d7Df6466D2Cdc"
        );
        assert_eq!(tx_info.value, 4.523128485832664e57);
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
