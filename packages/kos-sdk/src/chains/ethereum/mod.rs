pub mod address;
pub mod request;
pub mod transaction;

use crate::chain::{self, BaseChain};
use crate::chains::evm20;
use crate::models::{self, BroadcastResult, PathOptions, Transaction, TransactionRaw};

use kos_crypto::keypair::KeyPair;
use kos_crypto::secp256k1::Secp256k1KeyPair;
use kos_proto::options::ETHOptions;
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;

use rlp::Rlp;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use std::{ops::Div, str::FromStr};
use wasm_bindgen::prelude::*;
use web3::ethabi;
use web3::types::U256;

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct ETH {}

pub const SIGN_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub const BIP44_PATH: u32 = 60;
pub const CHAIN_ID: u64 = 1;
pub const DEFAULT_GAS_TRANSFER: u64 = 21000;

/// hash digest
pub fn hash_transaction(eth_tx: &transaction::Transaction) -> Result<Vec<u8>, Error> {
    let bytes = eth_tx.encode()?;
    let digest = ETH::hash(&bytes)?;
    Ok(digest)
}

pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Ethereum",
    symbol: "ETH",
    precision: 18,
    chain_code: 3,
};

#[wasm_bindgen]
impl ETH {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    #[wasm_bindgen(js_name = "random")]
    pub fn random() -> Result<KeyPair, Error> {
        let mut rng = rand::thread_rng();
        let kp = Secp256k1KeyPair::random(&mut rng);
        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromBytes")]
    pub fn keypair_from_bytes(private_key: &[u8]) -> Result<KeyPair, Error> {
        // copy to fixed length array
        let mut pk_slice = [0u8; 32];
        pk_slice.copy_from_slice(private_key);

        let kp = Secp256k1KeyPair::new(pk_slice);
        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "keypairFromMnemonic")]
    pub fn keypair_from_mnemonic(
        mnemonic: &str,
        path: &str,
        password: Option<String>,
    ) -> Result<KeyPair, Error> {
        let kp = Secp256k1KeyPair::new_from_mnemonic_phrase_with_path(
            mnemonic,
            path,
            password.as_deref(),
        )?;

        Ok(KeyPair::new_secp256k1(kp))
    }

    #[wasm_bindgen(js_name = "getAddressFromKeyPair")]
    pub fn get_address_from_keypair(kp: &KeyPair) -> Result<String, Error> {
        Ok(address::Address::from_keypair(kp).to_string())
    }

    #[wasm_bindgen(js_name = "getPath")]
    pub fn get_path(options: &PathOptions) -> Result<String, Error> {
        Ok(format!("m/44'/{}'/0'/0/{}", BIP44_PATH, options.index))
    }

    #[wasm_bindgen(js_name = "signDigest")]
    /// Sign digest data with the private key.
    pub fn sign_digest(digest: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let raw = keypair.sign_digest(digest);
        Ok(raw)
    }

    #[wasm_bindgen(js_name = "verifyDigest")]
    /// Verify Message signature
    pub fn verify_digest(_digest: &[u8], _signature: &[u8], _address: &str) -> Result<bool, Error> {
        // let message = Message::from_slice(message).map_err(|_| RecoveryError::InvalidMessage)?;
        // let recovery_id = RecoveryId::from_i32(recovery_id).map_err(|_| RecoveryError::InvalidSignature)?;
        // let signature =
        //     RecoverableSignature::from_compact(signature, recovery_id).map_err(|_| RecoveryError::InvalidSignature)?;
        // let public_key = CONTEXT
        //     .recover_ecdsa(&message, &signature)
        //     .map_err(|_| RecoveryError::InvalidSignature)?;

        // Ok(public_key_address(&public_key))
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Ethereum(eth_tx)) => {
                let mut new_tx = eth_tx.clone();

                // remove signature if any
                let mut eth_tx = eth_tx.clone();
                eth_tx.signature = None;

                let digest = hash_transaction(&eth_tx)?;
                let sig = ETH::sign_digest(digest.as_slice(), keypair)?;

                new_tx.signature = Some(RecoverableSignature::from_compact(
                    &sig[..64],
                    RecoveryId::from_i32(sig[64] as i32)?,
                )?);

                let new_hash = hash_transaction(&new_tx)?;
                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(new_hash)?,
                    data: Some(TransactionRaw::Ethereum(new_tx)),
                    signature: Some(hex::encode(sig)),
                };

                Ok(result)
            }
            _ => Err(Error::InvalidMessage(
                "not a ethereum transaction".to_string(),
            )),
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = kos_crypto::hash::keccak256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        ETH::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = ETH::message_hash(message)?;
        ETH::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<bool, Error> {
        let m = ETH::message_hash(message)?;
        ETH::verify_digest(&m, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    pub async fn get_balance(
        address: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("ETH"));

        let from: address::Address = address.try_into()?;

        match token {
            Some(key) if key != "ETH" => {
                let contract_address: address::Address = key.as_str().try_into()?;
                let contract = evm20::get_contract_evm20();
                let func = contract.function("balanceOf").map_err(|e| {
                    Error::InvalidMessage(format!("failed to get balanceOf function: {}", e))
                })?;

                let data = func
                    .encode_input(&[ethabi::Token::Address(from.into())])
                    .map_err(|e| Error::InvalidMessage(format!("failed to encode input: {}", e)))?;

                let result = request::call(&node, from, contract_address, data).await?;

                // Decode the output (the balance).
                let balance = match func.decode_output(&result).unwrap()[0].clone().into_uint() {
                    Some(b) => b,
                    _ => return Err(Error::ReqwestError("failed to decode output".to_string())),
                };

                Ok(balance.to_string().try_into()?)
            }
            _ => request::get_balance(&node, from).await,
        }
    }

    #[wasm_bindgen(js_name = "getGasPrice")]
    pub async fn gas_price(node_url: Option<String>) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("ETH"));
        let gas_price = request::gas_price(&node).await?;
        BigNumber::from_string(&gas_price.to_string())
    }

    fn get_options(options: Option<crate::models::SendOptions>) -> kos_proto::options::ETHOptions {
        match options.and_then(|opt| opt.data) {
            Some(crate::models::Options::Ethereum(op)) => op,
            _ => kos_proto::options::ETHOptions::default(),
        }
    }

    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("ETH"));

        // validate sender address
        let addr_sender = address::Address::from_str(&sender)?;
        let mut addr_receiver = address::Address::from_str(&receiver)?;
        let mut options = ETH::get_options(options);

        let token = options.token.as_deref().unwrap_or("ETH");
        let is_eth_token = token == "ETH";

        let mut amount_eth = amount.clone();
        // Update addr_receiver for non-ETH token.
        if !is_eth_token {
            // update contract data for token transfer
            let contract = evm20::get_contract_evm20();
            let func = contract.function("transfer").map_err(|e| {
                Error::InvalidMessage(format!("failed to get transfer function: {}", e))
            })?;

            let encoded = func
                .encode_input(&[
                    ethabi::Token::Address(addr_receiver.into()),
                    ethabi::Token::Uint(
                        U256::from_dec_str(&amount.to_string())
                            .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
                    ),
                ])
                .map_err(|e| Error::InvalidTransaction(e.to_string()))?;

            addr_receiver = address::Address::from_str(token)?;
            options.contract_data = Some(encoded);
            amount_eth = 0.into();
        } else if options.gas_limit.is_none() {
            options.gas_limit = Some(BigNumber::from(DEFAULT_GAS_TRANSFER));
        }

        let tx = ETH::build_tx(&node, addr_sender, addr_receiver, amount_eth, options).await?;

        let digest = hash_transaction(&tx)?;

        Ok(crate::models::Transaction {
            chain: chain::Chain::ETH,
            sender,
            hash: Hash::from_vec(digest)?,
            data: Some(TransactionRaw::Ethereum(tx)),
            signature: None,
        })
    }

    async fn build_tx(
        node: &str,
        sender: address::Address,
        receiver: address::Address,
        amount: BigNumber,
        options: ETHOptions,
    ) -> Result<transaction::Transaction, Error> {
        // update chain id if none
        let chain_id = options.chain_id.unwrap_or(CHAIN_ID);

        // compute nonce if none
        let nonce = match options.nonce {
            Some(value) if value != 0 => U256::from_dec_str(&value.to_string())
                .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
            _ => {
                let nonce = request::get_nonce(node, sender).await?;
                U256::from(nonce)
            }
        };

        let gas_price: Option<U256> = match options.gas_price {
            Some(value) => Some(
                U256::from_dec_str(&value.to_string())
                    .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
            ),
            None => {
                if options.legacy_type.unwrap_or(false) {
                    Some(request::gas_price(node).await?)
                } else {
                    None
                }
            }
        };

        let value = U256::from_dec_str(&amount.to_string())
            .map_err(|e| Error::InvalidNumberParse(e.to_string()))?;

        let gas_limit: U256 = match options.gas_limit {
            Some(value) => U256::from_dec_str(&value.to_string())
                .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
            None => {
                request::estimate_gas(
                    node,
                    sender,
                    receiver,
                    gas_price,
                    Some(value),
                    options.contract_data.to_owned(),
                )
                .await?
            }
        };

        let max_fee_per_gas: Option<U256> = match options.max_fee_per_gas {
            Some(value) => Some(
                U256::from_dec_str(&value.to_string())
                    .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
            ),
            None => {
                if !options.legacy_type.unwrap_or(false) {
                    Some(request::base_fee(node).await?)
                } else {
                    None
                }
            }
        };

        let max_priority_fee_per_gas: Option<U256> = match options.max_priority_fee_per_gas {
            Some(value) => Some(
                U256::from_dec_str(&value.to_string())
                    .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
            ),
            None => {
                if !options.legacy_type.unwrap_or(false) {
                    // use 10% of max_fee_per_gas for max_priority_fee_per_gas as default
                    Some(max_fee_per_gas.unwrap_or_default().div(U256::from(10)))
                } else {
                    None
                }
            }
        };

        Ok(transaction::Transaction {
            transaction_type: Some(if options.legacy_type.unwrap_or(false) {
                transaction::TransactionType::Legacy
            } else {
                transaction::TransactionType::EIP1559
            }),
            chain_id: Some(chain_id),
            nonce,
            from: Some(sender),
            to: Some(receiver),
            value,
            data: options.contract_data.unwrap_or_default(),
            gas: gas_limit,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            signature: None,
        })
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("ETH"));

        let eth_tx = match tx.data.to_owned() {
            Some(TransactionRaw::Ethereum(tx)) => tx,
            _ => return Err(Error::InvalidTransaction("Invalid transaction type".into())),
        };

        _ = request::broadcast(node.as_str(), eth_tx.encode()?).await?;

        Ok(BroadcastResult::new(tx))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        address: &str,
        option: Option<models::AddressOptions>,
    ) -> Result<bool, Error> {
        let addr = address::Address::from_str(address);
        let addr = match addr {
            Ok(addr) => addr.to_string().trim_start_matches("0x").to_string(),
            Err(_) => return Ok(false),
        };

        let option = option.unwrap_or_default();

        // Check if address checksum is required and if the address matches the expected format
        if option.check_summed.unwrap_or(false)
            && addr != address.to_string().trim_start_matches("0x")
        {
            return Ok(false);
        }

        Ok(true)
    }

    #[wasm_bindgen(js_name = "txFromRaw")]
    pub fn tx_from_raw(raw: &str) -> Result<crate::models::Transaction, Error> {
        let hex_tx = hex::decode(raw)?;
        let rlp = Rlp::new(&hex_tx);

        let tx = match transaction::Transaction::decode_legacy(&rlp) {
            Ok(tx) => tx,
            Err(_) => {
                let rlp = Rlp::new(&hex_tx[2..]);
                self::transaction::Transaction::decode_eip155(rlp).map_err(|e| {
                    Error::InvalidTransaction(format!("failed to decode transaction: {}", e))
                })?
            }
        };

        let signature = tx.signature.unwrap().to_standard().to_string();

        let digest = hash_transaction(&tx)?;

        Ok(crate::models::Transaction {
            chain: chain::Chain::ETH,
            sender: "".to_string(), //TODO: implement sender on eth decode
            hash: Hash::from_vec(digest)?,
            data: Some(TransactionRaw::Ethereum(tx)),
            signature: Some(signature),
        })
    }

    #[wasm_bindgen(js_name = "txFromJson")]
    pub fn tx_from_json(raw: &str) -> Result<crate::models::Transaction, Error> {
        // build expected send result
        let tx: transaction::Transaction = serde_json::from_str(raw)?;

        let digest = hash_transaction(&tx)?;

        let sender = match tx.from {
            Some(addr) => addr.to_string(),
            None => "".to_string(),
        };

        let signature = tx.signature.unwrap().to_standard().to_string();

        Ok(crate::models::Transaction {
            chain: chain::Chain::ETH,
            sender,
            hash: Hash::from_vec(digest)?,
            data: Some(TransactionRaw::Ethereum(tx)),
            signature: Some(signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenvy;
    use hex::FromHex;
    use kos_types::Bytes32;
    use std::sync::Once;

    const DEFAULT_PRIVATE_KEY: &str =
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
    const DEFAULT_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const DEFAULT_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    static _INIT: Once = Once::new();

    fn _init() {
        _INIT.call_once(|| {
            dotenvy::from_filename(".env.nodes").ok();
        });
    }

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_private_key() {
        let address = ETH::get_address_from_keypair(&get_default_secret()).unwrap();

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
            let path = ETH::get_path(&PathOptions::new(index)).unwrap();
            let kp = ETH::keypair_from_mnemonic(DEFAULT_MNEMONIC, &path, None).unwrap();
            let addr = ETH::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }

    #[test]
    fn test_send_and_sign() {
        let options = models::SendOptions {
            data: Some(models::Options::Ethereum(kos_proto::options::ETHOptions {
                chain_id: Some(1),
                nonce: Some(100),
                max_fee_per_gas: Some("1000000000".try_into().unwrap()),
                max_priority_fee_per_gas: Some("1000000000".try_into().unwrap()),
                ..Default::default()
            })),
        };

        let tx = tokio_test::block_on(ETH::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "c2c9b955cf8394fa9434ba812e69f2297c23c16a261a915fa3f1a18adf3fae63"
        );

        let signed = ETH::sign(tx, &get_default_secret());
        assert!(signed.is_ok());
        assert_eq!(
            signed.unwrap().hash.to_string(),
            "87eab8c8201462ac4872200dfebe841aa77bdc0cc0e5310542c7f319dd304fdf"
        );
    }

    #[test]
    fn test_send_erc20() {
        let options = models::SendOptions {
            data: Some(models::Options::Ethereum(kos_proto::options::ETHOptions {
                chain_id: Some(1),
                nonce: Some(100),
                token: Some("0xc12d1c73ee7dc3615ba4e37e4abfdbddfa38907e".to_string()),
                gas_limit: Some(1000000.into()),
                gas_price: Some(0.into()),
                max_fee_per_gas: Some(0.into()),
                max_priority_fee_per_gas: Some(0.into()),
                ..Default::default()
            })),
        };

        let tx = tokio_test::block_on(ETH::send(
            DEFAULT_ADDRESS.to_string(),
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_string(),
            "1000".try_into().unwrap(),
            Some(options),
            None,
        ))
        .unwrap();

        assert_eq!(
            tx.hash.to_string(),
            "fa2b84b45d28888c43c0bda80000e4a4d2040017f3b6e4a31e7d8a4ace27db29"
        );

        let eth_tx = match tx.data.clone() {
            Some(models::TransactionRaw::Ethereum(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(eth_tx.value.to_string(), "0");
        assert_eq!(hex::encode(eth_tx.data), "a9059cbb0000000000000000000000006fac4d18c912343bf86fa7049364dd4e424ab9c000000000000000000000000000000000000000000000000000000000000003e8");

        let signed = ETH::sign(tx, &get_default_secret());
        assert!(signed.is_ok());
        assert_eq!(
            signed.unwrap().hash.to_string(),
            "f4c27caf4a9e3718d217f315e8fed3f9b739fa61c78e5ab43a7ca7d4fd1c010f"
        );
    }

    #[test]
    fn test_get_balance() {
        let balance = tokio_test::block_on(ETH::get_balance(DEFAULT_ADDRESS, None, None)).unwrap();

        assert!(balance.to_i64() > 0);
    }

    #[test]
    fn test_get_balance_erc20() {
        let balance = tokio_test::block_on(ETH::get_balance(
            DEFAULT_ADDRESS,
            Some("0xC12D1c73eE7DC3615BA4e37E4ABFdbDDFA38907E".to_string()),
            None,
        ));
        assert!(balance.is_ok());

        assert!(balance.unwrap().to_i64() > 100);
    }

    #[test]
    fn test_validate_address_ok() {
        let list = [
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
            "9858EfFD232B4033E47d90003D41EC34EcaEda94", // no 0x prefix as valid
        ];

        for addr in list {
            let valid = ETH::validate_address(addr, None).unwrap();
            assert!(valid);
        }

        // check summed
        for addr in list {
            let valid = ETH::validate_address(
                addr,
                Some(models::AddressOptions::new(None, None, Some(true))),
            )
            .unwrap();
            assert_eq!(valid, true, "address: {}", addr);
        }
    }

    #[test]
    fn test_validate_address_fail() {
        let list = [
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda95", // wrong check sum
            &"0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_lowercase(), // all lower case
        ];

        // check summed
        for addr in list {
            let valid = ETH::validate_address(
                addr,
                Some(models::AddressOptions::new(None, None, Some(true))),
            )
            .unwrap();
            assert_eq!(valid, false, "address: {}", addr);
        }

        // wrong size
        let list = [
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda9", // hex convert wrong parity
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda941", // hex convert wrong parity
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94Ab", // hex convert ok, wrong length
        ];

        // check summed
        for addr in list {
            let valid = ETH::validate_address(&addr, None).unwrap();
            assert_eq!(valid, false, "address: {}", addr);
        }
    }

    #[test]
    fn test_decode_rlp_tx() {
        let raw_tx = "af02ed0182012884019716f7850e60f86055827530944cbeee256240c92a9ad920ea6f4d7df6466d2cdc0180c0808080";
        let tx = ETH::tx_from_raw(raw_tx).unwrap();

        assert_eq!(tx.chain, chain::Chain::ETH);

        let eth_tx = match tx.data {
            Some(TransactionRaw::Ethereum(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(eth_tx.chain_id, Some(1));
        assert_eq!(eth_tx.nonce, U256::from_dec_str("296").unwrap());
        assert_eq!(
            eth_tx.to.unwrap().to_string(),
            "0x4cBeee256240c92A9ad920ea6f4d7Df6466D2Cdc"
        );
        assert_eq!(eth_tx.gas, U256::from(30000));
        assert_eq!(eth_tx.value, U256::from_dec_str("1").unwrap());
        assert_eq!(eth_tx.signature, None);
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
        let tx = ETH::tx_from_json(json).unwrap();

        assert_eq!(tx.chain, chain::Chain::ETH);

        let eth_tx = match tx.data {
            Some(TransactionRaw::Ethereum(tx)) => tx,
            _ => panic!("invalid tx"),
        };

        assert_eq!(eth_tx.chain_id, None);
        assert_eq!(eth_tx.nonce, U256::from_dec_str("0").unwrap());
        assert_eq!(
            eth_tx.from.unwrap().to_string(),
            "0x4cBeee256240c92A9ad920ea6f4d7Df6466D2Cdc"
        );
        assert_eq!(
            eth_tx.to.unwrap().to_string(),
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );
        assert_eq!(eth_tx.gas, U256::from(0));
        assert_eq!(eth_tx.value, U256::from(0));
        assert_eq!(eth_tx.signature, None);
    }
}
