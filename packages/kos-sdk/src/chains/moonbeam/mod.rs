use super::ETHTransaction;
use super::ETH;

use crate::chain::{BaseChain, Chain};
use crate::models::PathOptions;
use crate::models::{self, BroadcastResult, TransactionRaw};

use kos_crypto::keypair::KeyPair;
use kos_types::error::Error;
use kos_types::number::BigNumber;

use crate::chain;
use crate::chains::ethereum::transaction;
use kos_types::hash::Hash;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]

pub struct GLMR {}

pub const CHAIN_ID: u64 = 1284;

pub fn hash_transaction(moonbeam_tx: &transaction::Transaction) -> Result<Vec<u8>, Error> {
    let bytes = moonbeam_tx.encode()?;
    let digest = GLMR::hash(&bytes)?;
    Ok(digest)
}

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Moonbeam",
    symbol: "GLMR",
    precision: 18,
    chain_code: 34,
};

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Transaction {
    pub eth: ETHTransaction,
}

fn convert_options(
    options: Option<crate::models::SendOptions>,
) -> Option<crate::models::SendOptions> {
    let mut data = match options.and_then(|opt| opt.data) {
        Some(crate::models::Options::Moonbeam(op)) => op.eth,
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
        Some(TransactionRaw::Moonbeam(tx_moonbeam)) => {
            Ok(tx.new_data(Chain::GLMR, TransactionRaw::Ethereum(tx_moonbeam.eth)))
        }
        Some(TransactionRaw::Ethereum(tx_eth)) => Ok(tx.new_data(
            Chain::GLMR,
            TransactionRaw::Moonbeam(Transaction { eth: tx_eth }),
        )),
        _ => Err(Error::InvalidTransaction(
            "Invalid Transaction Type".to_string(),
        )),
    }
}

#[wasm_bindgen]
impl GLMR {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        ETH::random()
    }

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        ETH::keypair_from_bytes(private_key)
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
    pub fn get_path(options: &PathOptions) -> Result<String, Error> {
        ETH::get_path(options)
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        ETH::sign_digest(digest, keypair)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(digest: &[u8], signature: &[u8], address: &str) -> Result<bool, Error> {
        ETH::verify_digest(digest, signature, address)
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: models::Transaction, keypair: &KeyPair) -> Result<models::Transaction, Error> {
        let result = ETH::sign(convert_transaction(tx)?, keypair);

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
    ) -> Result<bool, Error> {
        ETH::verify_message_signature(message, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("GLMR"));
        ETH::get_balance(address, token, Some(node)).await
    }

    #[wasm_bindgen(js_name = "getGasPrice")]
    pub async fn gas_price(node_url: Option<String>) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("GLMR"));
        ETH::gas_price(Some(node)).await
    }
    #[wasm_bindgen(js_name = "send")]
    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<models::Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("GLMR"));
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
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("GLMR"));
        let result = ETH::broadcast(tx, Some(node)).await?;
        Ok(BroadcastResult::new(convert_transaction(result.tx)?))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        ETH::validate_address(address, option)
    }

    #[wasm_bindgen(js_name = "txFromJson")]
    pub fn tx_from_json(raw: &str) -> Result<crate::models::Transaction, Error> {
        let tx: transaction::Transaction = serde_json::from_str(raw)?;
        let digest = hash_transaction(&tx)?;

        let sender = match tx.from {
            Some(addr) => addr.to_string(),
            None => "".to_string(),
        };

        let signature = tx.signature.map(|sig| sig.to_standard().to_string());

        Ok(crate::models::Transaction {
            chain: chain::Chain::GLMR,
            sender,
            hash: Hash::from_vec(digest)?,
            data: Some(TransactionRaw::Ethereum(tx)),
            signature,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use kos_crypto::secp256k1::Secp256k1KeyPair;
    use kos_types::Bytes32;
    use web3::types::U256;
    const DEFAULT_PRIVATE_KEY: &str =
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
    const DEFAULT_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const DEFAULT_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn init() {
        std::env::set_var("NODE_GLMR", "https://moonbeam.node.klever.io");
    }

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_private_key() {
        let address = GLMR::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_validate_bip44() {
        let v = vec![
            (0, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            (1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            (2, "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"),
            (3, "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E"),
            (4, "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA"),
        ];

        for (index, expected_addr) in v {
            let path = GLMR::get_path(&PathOptions::new(index)).unwrap();
            let kp = GLMR::keypair_from_mnemonic(DEFAULT_MNEMONIC, &path, None).unwrap();
            let addr = GLMR::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }

    #[test]
    fn test_send_and_sign() {
        init();
        let options = models::SendOptions {
            data: Some(models::Options::Moonbeam(kos_proto::options::GLMROptions {
                eth: kos_proto::options::ETHOptions {
                    chain_id: Some(CHAIN_ID),
                    nonce: Some(100),
                    max_fee_per_gas: Some("1000000000".try_into().unwrap()),
                    max_priority_fee_per_gas: Some("1000000000".try_into().unwrap()),
                    ..Default::default()
                },
            })),
        };

        let tx = tokio_test::block_on(GLMR::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "3f46bcae2c147f935ab04f67e8fd3dce4e00a678d28dba02032f20e907d50b39"
        );

        let signed = GLMR::sign(tx, &get_default_secret());

        assert!(signed.is_ok());

        assert_eq!(
            signed.unwrap().hash.to_string(),
            "16a2934180aa7888a979fcabfe0853a42241eaaa1d18b005923ae7875072ae23"
        );
    }

    #[test]
    fn test_send_erc20() {
        init();
        let options = models::SendOptions {
            data: Some(models::Options::Moonbeam(kos_proto::options::GLMROptions {
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

        let tx = tokio_test::block_on(GLMR::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "8c27958a5dee222dede52d0dbcc529040443af6a8317890b8d8acb5bbd293ec6"
        );

        let moonbeam_tx = match tx.data.clone() {
            Some(models::TransactionRaw::Moonbeam(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(moonbeam_tx.eth.value.to_string(), "0");
        assert_eq!(hex::encode(moonbeam_tx.eth.data), "a9059cbb0000000000000000000000006fac4d18c912343bf86fa7049364dd4e424ab9c000000000000000000000000000000000000000000000000000000000000003e8");

        let signed = GLMR::sign(tx, &get_default_secret());
        assert!(signed.is_ok());
        assert_eq!(
            signed.unwrap().hash.to_string(),
            "aedb7da9691d1a7968855e91cb2161b1d83393aec339b886ca327033e8ce9894"
        );
    }

    #[test]
    fn test_get_balance() {
        init();
        let balance = tokio_test::block_on(GLMR::get_balance(DEFAULT_ADDRESS, None, None)).unwrap();

        assert!(balance.to_i64() >= 0);
    }

    #[test]
    fn test_get_balance_erc20() {
        init();
        let balance = tokio_test::block_on(GLMR::get_balance(
            DEFAULT_ADDRESS,
            Some("0x0000000000000000000000000000000000000802".to_string()),
            None,
        ));
        assert!(balance.is_ok());

        assert_eq!(balance.unwrap().to_string(), "0");
    }

    #[test]
    fn test_decode_json() {
        let json = r#"{
        "from":"0x4cbeee256240c92a9ad920ea6f4d7df6466d2cdc",
        "maxPriorityFeePerGas":null,"maxFeePerGas":null,
         "gas": "0x00",
         "value": "0x00",
         "data":"0xa9059cbb000000000000000000000000ac4145fef6c828e8ae017207ad944c988ccb2cf700000000000000000000000000000000000000000000000000000000000f4240",
         "to":"0xdac17f958d2ee523a2206206994597c13d831ec7",
         "nonce":"0x00"}"#;
        let tx = GLMR::tx_from_json(json).unwrap();

        assert_eq!(tx.chain, chain::Chain::GLMR);

        let moonbeam_tx = match tx.data {
            Some(TransactionRaw::Ethereum(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(moonbeam_tx.chain_id, None);
        assert_eq!(moonbeam_tx.nonce, U256::from_dec_str("0").unwrap());
        assert_eq!(
            moonbeam_tx.from.unwrap().to_string(),
            "0x4cBeee256240c92A9ad920ea6f4d7Df6466D2Cdc"
        );
        assert_eq!(
            moonbeam_tx.to.unwrap().to_string(),
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );
        assert_eq!(moonbeam_tx.gas, U256::from(0));
        assert_eq!(moonbeam_tx.value, U256::from(0));
        assert_eq!(moonbeam_tx.signature, None);
    }
}
