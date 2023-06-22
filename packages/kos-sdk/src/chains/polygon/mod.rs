use super::ETHTransaction;
use super::ETH;

use crate::chain::BaseChain;
use crate::models::{self, BroadcastResult, TransactionRaw};

use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct MATIC {}

pub const CHAIN_ID: u64 = 137;

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Polygon",
    symbol: "MATIC",
    precision: 18,
    chain_code: 28,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Transaction {
    pub eth: ETHTransaction,
}

fn convert_options(
    options: Option<crate::models::SendOptions>,
) -> Option<crate::models::SendOptions> {
    let mut data = match options.and_then(|opt| opt.data) {
        Some(crate::models::Options::Polygon(op)) => op.eth,
        _ => kos_proto::options::ETHOptions::default(),
    };

    if data.chain_id.is_none() {
        data.chain_id = Some(CHAIN_ID)
    };

    Some(crate::models::SendOptions::new(
        crate::models::Options::Ethereum(data),
    ))
}

fn convert_transaction(tx: models::Transaction) -> Result<models::Transaction, Error> {
    match tx.data.clone() {
        Some(TransactionRaw::Polygon(tx_polygon)) => {
            Ok(tx.new_data(TransactionRaw::Ethereum(tx_polygon.eth)))
        }
        Some(TransactionRaw::Ethereum(tx_eth)) => {
            Ok(tx.new_data(TransactionRaw::Polygon(Transaction { eth: tx_eth })))
        }
        _ => Err(Error::InvalidTransaction(
            "Invalid Transaction Type".to_string(),
        )),
    }
}

#[wasm_bindgen]
impl MATIC {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        ETH::random()
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        ETH::keypair_from_mnemonic(mnemonic, path, password)
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        ETH::get_address_from_keypair(kp)
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(index: u32) -> Result<String, Error> {
        ETH::get_path(index)
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        ETH::sign_digest(digest, keypair)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], address: &str) -> Result<(), Error> {
        ETH::verify_digest(digest, signature, address)
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: models::Transaction, keypair: &KeyPair) -> Result<models::Transaction, Error> {
        let result = ETH::sign(convert_transaction(tx)?, keypair);

        // convert back to polygon tx enum
        convert_transaction(result?)
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        ETH::hash(message)
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        ETH::message_hash(message)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        ETH::sign_message(message, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<(), Error> {
        ETH::verify_message_signature(message, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("MATIC"));
        ETH::get_balance(address, token, Some(node)).await
    }

    #[wasm_bindgen(js_name = "getGasPrice")]
    pub async fn gas_price(node_url: Option<String>) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("MATIC"));
        ETH::gas_price(Some(node)).await
    }

    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<models::Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("MATIC"));
        let result = ETH::send(
            sender,
            receiver,
            amount,
            convert_options(options),
            Some(node),
        )
        .await?;
        convert_transaction(result)
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("MATIC"));
        let result = ETH::broadcast(tx, Some(node)).await?;
        Ok(BroadcastResult::new(convert_transaction(result.tx)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use kos_crypto::secp256k1::Secp256k1KeyPair;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
    const DEFAULT_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const DEFAULT_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_private_key() {
        let address = MATIC::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_validate_tron_bip44() {
        let v = vec![
            (0, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            (1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            (2, "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"),
            (3, "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E"),
            (4, "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA"),
        ];

        for (index, expected_addr) in v {
            let path = MATIC::get_path(index).unwrap();
            let kp = MATIC::keypair_from_mnemonic(DEFAULT_MNEMONIC, &path, None).unwrap();
            let addr = MATIC::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }

    #[test]
    fn test_send_end_sign() {
        let options = models::SendOptions {
            data: Some(models::Options::Polygon(kos_proto::options::MATICOptions {
                eth: kos_proto::options::ETHOptions {
                    chain_id: Some(CHAIN_ID),
                    nonce: Some(100),
                    max_fee_per_gas: Some("1000000000".try_into().unwrap()),
                    max_priority_fee_per_gas: Some("1000000000".try_into().unwrap()),
                    ..Default::default()
                },
            })),
        };

        let tx = tokio_test::block_on(MATIC::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "ce4fdd2a2d7767a4d4df8533bd1218a51755e6d15f814a20d3fa834e27c8602c"
        );

        let signed = MATIC::sign(tx, &get_default_secret());
        assert!(signed.is_ok());
        assert_eq!(
            signed.unwrap().hash.to_string(),
            "df531bd12423bc8c2a047c01a30b1513a41b47e81d75904a703bdb1d8962bd22"
        );
    }

    #[test]
    fn test_send_erc20() {
        let options = models::SendOptions {
            data: Some(models::Options::Polygon(kos_proto::options::MATICOptions {
                eth: kos_proto::options::ETHOptions {
                    chain_id: Some(CHAIN_ID),
                    nonce: Some(100),
                    token: Some("0xc12d1c73ee7dc3615ba4e37e4abfdbddfa38907e".to_string()),
                    gas_limit: Some(1000000.into()),
                    gas_price: Some(0.into()),
                    max_fee_per_gas: Some(0.into()),
                    max_priority_fee_per_gas: Some(0.into()),
                    ..Default::default()
                },
            })),
        };

        let tx = tokio_test::block_on(MATIC::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "99851c74c0bd74345c5361b46ac128a3d37c3af1998af53f8c91740f3b90d6e8"
        );

        let polygon_tx = match tx.data.clone() {
            Some(models::TransactionRaw::Polygon(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(polygon_tx.eth.value.to_string(), "0");
        assert_eq!(hex::encode(polygon_tx.eth.data), "23b872dd0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda940000000000000000000000006fac4d18c912343bf86fa7049364dd4e424ab9c000000000000000000000000000000000000000000000000000000000000003e8");

        let signed = MATIC::sign(tx, &get_default_secret());
        assert!(signed.is_ok());
        assert_eq!(
            signed.unwrap().hash.to_string(),
            "af025f06a080ce062313f662a67adb34ccf700777ef1120f9f8d44ed269e83e0"
        );
    }

    #[test]
    fn test_get_balance() {
        let balance =
            tokio_test::block_on(MATIC::get_balance(DEFAULT_ADDRESS, None, None)).unwrap();

        assert!(balance.to_i64() > 100);
    }

    #[test]
    fn test_get_balance_erc20() {
        let balance = tokio_test::block_on(MATIC::get_balance(
            DEFAULT_ADDRESS,
            Some("0x19a935cbaaa4099072479d521962588d7857d717".to_string()),
            None,
        ));
        assert!(balance.is_ok());

        assert_eq!(balance.unwrap().to_string(), "1000000000000000000000");
    }
}
