mod models;

use crate::chains::eth::models::EthereumTransaction;
use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::{Chain, ChainError, Transaction, TxInfo, TxType};
use crate::crypto::hash::keccak256_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use crate::crypto::{bip32, secp256k1};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(crate) const ETH_ADDR_SIZE: usize = 20;
const ETH_MESSAGE_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub struct ETH {
    pub chaincode: u32,
    pub symbol: String,
    pub name: String,
}

impl ETH {
    pub fn new() -> Self {
        ETH::new_eth_based(1, "ETH", "Ethereum")
    }

    pub fn new_eth_based(chaincode: u32, symbol: &str, name: &str) -> Self {
        ETH {
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
    fn get_name(&self) -> &str {
        return self.name.as_str();
    }

    fn get_symbol(&self) -> &str {
        return self.symbol.as_str();
    }

    fn get_decimals(&self) -> u32 {
        return 18;
    }

    fn mnemonic_to_seed(&self, mnemonic: String, password: String) -> Result<Vec<u8>, ChainError> {
        Ok(bip32::mnemonic_to_seed(mnemonic, password)?)
    }

    fn derive(&self, seed: Vec<u8>, path: String) -> Result<Vec<u8>, ChainError> {
        let pvk = bip32::derive(&seed, path)?;
        Ok(Vec::from(pvk))
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

        return ETH::addr_bytes_to_string(address_bytes);
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

    fn sign_message(&self, private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ChainError> {
        let to_sign = [
            ETH_MESSAGE_PREFIX,
            message.len().to_string().as_bytes(),
            &message[..],
        ]
        .concat();
        let hashed = keccak256_digest(&to_sign[..]);
        let signature = self.sign_raw(private_key, hashed.to_vec())?;
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
        let pvk = eth.derive(seed, "m/44'/60'/0'/0/0".to_string()).unwrap();
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
        };

        let _ = eth.sign_tx(pvk, tx).unwrap();
    }

    #[test]
    fn test_sign_london_tx() {
        let raw_tx = hex::decode("b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080").unwrap();
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();
        let eth = super::ETH::new_eth_based(56, "ETH", "Ethereum");

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
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
            "0x84ae7937b285035f6cccc58252089498de4c8381"
        );
        assert_eq!(tx_info.value, 0.1);
    }
}
