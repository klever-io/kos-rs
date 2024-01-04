pub mod address;
pub mod requests;

use std::str::FromStr;

use crate::{
    chain::{self, BaseChain},
    chains::ethereum::address::Address as ETHAddress,
    chains::evm20,
    models::{BroadcastResult, PathOptions, Transaction, TransactionRaw},
};

use kos_crypto::{keypair::KeyPair, secp256k1::Secp256k1KeyPair};
use kos_types::error::Error;
use kos_types::hash::Hash;
use kos_types::number::BigNumber;

use wasm_bindgen::prelude::*;
use web3::{ethabi, types::U256};

#[derive(Debug, Copy, Clone)]
#[wasm_bindgen]
pub struct TRX {}

pub const SIGN_PREFIX: &[u8; 22] = b"\x19TRON Signed Message:\n";
pub const BIP44_PATH: u32 = 195;
pub const BASE_CHAIN: BaseChain = BaseChain {
    name: "Tron",
    symbol: "TRX",
    precision: 6,
    chain_code: 1,
};

#[wasm_bindgen]
impl TRX {
    #[wasm_bindgen(js_name = "baseChain")]
    pub fn base_chain() -> BaseChain {
        BASE_CHAIN
    }

    fn get_options(options: Option<crate::models::SendOptions>) -> kos_proto::options::TRXOptions {
        match options.and_then(|opt| opt.data) {
            Some(crate::models::Options::Tron(op)) => op,
            _ => kos_proto::options::TRXOptions::default(),
        }
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
        let index = options.index;

        let is_legacy = options.is_legacy.unwrap_or(false);

        if is_legacy {
            Ok(format!("m/44'/{}'/{}'", BIP44_PATH, index))
        } else {
            // use account 0 index X
            Ok(format!("m/44'/{}'/0'/0/{}", BIP44_PATH, index))
        }
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
        todo!()
    }

    #[wasm_bindgen(js_name = "sign")]
    /// Hash and Sign data with the private key.
    pub fn sign(tx: Transaction, keypair: &KeyPair) -> Result<Transaction, Error> {
        match tx.data {
            Some(TransactionRaw::Tron(trx_tx)) => {
                let mut new_tx = trx_tx.clone();
                let digest = TRX::hash_transaction(&trx_tx)?;
                let sig = TRX::sign_digest(digest.as_slice(), keypair)?;

                new_tx.signature.push(sig);
                let result = Transaction {
                    chain: tx.chain,
                    sender: tx.sender,
                    hash: Hash::from_vec(digest)?,
                    data: Some(TransactionRaw::Tron(new_tx)),
                };

                Ok(result)
            }
            _ => Err(Error::InvalidMessage("not a tron transaction".to_string())),
        }
    }

    fn hash_transaction(tx: &kos_proto::tron::Transaction) -> Result<Vec<u8>, Error> {
        if let Some(raw_data) = &tx.raw_data {
            let bytes = kos_proto::write_message(raw_data);
            TRX::hash(&bytes)
        } else {
            Err(Error::InvalidTransaction("trx raw_data".to_string()))
        }
    }

    #[wasm_bindgen(js_name = "hash")]
    /// hash digest
    pub fn hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = kos_crypto::hash::sha256(message);
        Ok(digest.to_vec())
    }

    #[wasm_bindgen(js_name = "messageHash")]
    /// Append prefix and hash the message
    pub fn message_hash(message: &[u8]) -> Result<Vec<u8>, Error> {
        let to_sign = [SIGN_PREFIX, message.len().to_string().as_bytes(), message].concat();

        TRX::hash(&to_sign)
    }

    #[wasm_bindgen(js_name = "signMessage")]
    /// Sign Message with the private key.
    pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<Vec<u8>, Error> {
        let m = TRX::message_hash(message)?;
        TRX::sign_digest(&m, keypair)
    }

    #[wasm_bindgen(js_name = "verifyMessageSignature")]
    /// Verify Message signature
    pub fn verify_message_signature(
        message: &[u8],
        signature: &[u8],
        address: &str,
    ) -> Result<bool, Error> {
        let m = TRX::message_hash(message)?;
        TRX::verify_digest(&m, signature, address)
    }

    #[wasm_bindgen(js_name = "getBalance")]
    /// Get balance of address and token
    /// If token is None, it will return balance of native token
    /// If token is Some, it will return balance of token
    /// If node_url is None, it will use default node url
    pub async fn get_balance(
        addr: &str,
        token: Option<String>,
        node_url: Option<String>,
    ) -> Result<BigNumber, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("TRX"));

        let acc_address = address::Address::from_str(addr)?;

        // check if TRC20 -> trigger contract instead todo!()
        let acc = requests::get_account(&node, &acc_address.to_hex_address()).await?;

        Ok(match token {
            Some(key) if key != "TRX" => match acc.asset_v2.get(&key) {
                Some(value) => BigNumber::from(*value),
                None => BigNumber::from(0),
            },
            _ => BigNumber::from(acc.balance),
        })
    }

    async fn check_valid_address(
        valid_address: &bool,
        addr_sender: &address::Address,
        addr_receiver: &address::Address,
        amount: &BigNumber,
        token: &str,
        node: &str,
    ) -> Result<kos_proto::tron::Transaction, Error> {
        if !valid_address {
            let contract = kos_proto::tron::TransferAssetContract {
                owner_address: addr_sender.as_bytes().to_vec(),
                to_address: addr_receiver.as_bytes().to_vec(),
                amount: amount.to_i64(),
                asset_name: token.as_bytes().to_vec(),
            };
            let transaction = requests::create_asset_transfer(node, contract).await?;
            return Ok(transaction);
        }
        use ethabi;
        use requests;

        let contract = evm20::get_contract_evm20();
        let func = contract.function("transfer").map_err(|e| {
            Error::InvalidMessage(format!("failed to get transferFrom function: {}", e))
        })?;

        let to_address = *ETHAddress::from_bytes(addr_receiver.as_tvm_bytes());
        let encoded = func
            .encode_input(&[
                ethabi::Token::Address(to_address.into()),
                ethabi::Token::Uint(
                    U256::from_dec_str(&amount.to_string())
                        .map_err(|e| Error::InvalidNumberParse(e.to_string()))?,
                ),
            ])
            .map_err(|e| Error::InvalidTransaction(e.to_string()))?;
        let contract_address = address::Address::from_str(token)?;

        let contract = kos_proto::tron::TriggerSmartContract {
            owner_address: addr_sender.as_bytes().to_vec(),
            contract_address: contract_address.as_bytes().to_vec(),
            data: encoded,
            call_token_value: 0,
            call_value: 0,
            token_id: 0,
        };

        let extended = requests::CreateTRC20TransferOptions {
            contract,
            // TODO: estimate fee limit, for now use 100 TRX
            fee_limit: 100000000,
        };
        let transaction = requests::create_trc20_transfer(node, extended).await?;
        Ok(transaction)
    }

    /// create a send transaction network
    #[wasm_bindgen(js_name = "send")]
    pub async fn send(
        sender: String,
        receiver: String,
        amount: BigNumber,
        options: Option<crate::models::SendOptions>,
        node_url: Option<String>,
    ) -> Result<crate::models::Transaction, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("TRX"));
        let addr_sender = address::Address::from_str(&sender)?;
        let addr_receiver = address::Address::from_str(&receiver)?;

        let options = TRX::get_options(options);

        let tx: kos_proto::tron::Transaction = match options.token {
            Some(token) if token != "TRX" => {
                // Check if TRC20 transfer
                let valid_address = TRX::validate_address(&token, None)?;
                Self::check_valid_address(
                    &valid_address,
                    &addr_sender,
                    &addr_receiver,
                    &amount,
                    &token,
                    &node,
                )
                .await?
            }
            _ => {
                let contract = kos_proto::tron::TransferContract {
                    owner_address: addr_sender.as_bytes().to_vec(),
                    to_address: addr_receiver.as_bytes().to_vec(),
                    amount: amount.to_i64(),
                };

                requests::create_transfer(&node, contract).await?
            }
        };

        // update memo field
        let tx = match options.memo {
            Some(memo) => {
                let mut tx = tx.clone();
                tx.raw_data.as_mut().unwrap().data = memo.as_bytes().to_vec();
                tx
            }
            None => tx,
        };

        let digest = TRX::hash_transaction(&tx)?;

        Ok(crate::models::Transaction {
            chain: chain::Chain::TRX,
            sender,
            hash: Hash::from_vec(digest)?,
            data: Some(TransactionRaw::Tron(tx)),
        })
    }

    #[wasm_bindgen(js_name = "broadcast")]
    pub async fn broadcast(
        tx: crate::models::Transaction,
        node_url: Option<String>,
    ) -> Result<BroadcastResult, Error> {
        let node = node_url.unwrap_or_else(|| crate::utils::get_node_url("TRX"));

        let raw = tx
            .data
            .clone()
            .ok_or_else(|| Error::ReqwestError("Missing transaction data".into()))?;

        let result = requests::broadcast(node.as_str(), raw.try_into()?).await?;

        if let Some(false) = result.get("result").and_then(|v| v.as_bool()) {
            let error_message = result
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("no message");
            return Err(Error::InvalidTransaction(format!(
                "Expected successful broadcast, got: {:?}",
                error_message
            )));
        }

        Ok(BroadcastResult::new(crate::models::Transaction {
            chain: tx.chain,
            sender: tx.sender,
            hash: tx.hash,
            data: tx.data,
        }))
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(
        addr: &str,
        _option: Option<crate::models::AddressOptions>,
    ) -> Result<bool, Error> {
        if addr.len() == address::ADDRESS_LEN_STR
            && addr.starts_with(address::ADDRESS_TYPE_PREFIX_STR)
        {
            let check = address::b58decode_check(addr);
            if check.is_err() {
                return Ok(false);
            }

            let check = check.unwrap();

            // check mainnet prefix
            if check[0] == address::ADDRESS_TYPE_PREFIX {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use crate::models::SendOptions;

    use super::*;
    use hex::FromHex;
    use kos_types::Bytes32;

    const DEFAULT_PRIVATE_KEY: &str =
        "b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28";
    const DEFAULT_ADDRESS: &str = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";

    fn get_default_secret() -> KeyPair {
        let b = Bytes32::from_hex(DEFAULT_PRIVATE_KEY).unwrap();
        let kp = Secp256k1KeyPair::new(b.into());
        KeyPair::new_secp256k1(kp)
    }

    #[test]
    fn test_address_from_mnemonic() {
        let path = TRX::get_path(&PathOptions::new(0)).unwrap();
        let kp = TRX::keypair_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", &path, None).unwrap();
        let address = TRX::get_address_from_keypair(&kp).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_address_from_private_key() {
        let address = TRX::get_address_from_keypair(&get_default_secret()).unwrap();

        assert_eq!(DEFAULT_ADDRESS, address);
    }

    #[test]
    fn test_get_balance() {
        let balance = tokio_test::block_on(TRX::get_balance(
            "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb",
            Some("TRX".to_string()),
            None,
        ))
        .unwrap();
        println!("balance: {}", balance.to_string());

        assert!(balance.to_number() > 0 as f64);
    }

    #[test]
    fn test_send() {
        let result = tokio_test::block_on(TRX::send(
            "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX".to_string(),
            DEFAULT_ADDRESS.to_string(),
            BigNumber::from(10),
            None,
            None,
        ));

        assert!(result.is_ok());
        let t = result.unwrap().clone();
        match t.clone().data {
            Some(TransactionRaw::Tron(tx)) => {
                let raw = &tx.raw_data.unwrap();
                assert_eq!(raw.contract.len(), 1);
                let c: kos_proto::tron::TransferContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();

                assert_eq!(c.amount, 10);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_send_trc20() {
        // create TRX send options
        let trx_options = kos_proto::options::TRXOptions {
            token: Some("TKk6DLX1xWRKHjDhHfdyQKefnP1WUppEXB".to_string()),
            ..Default::default()
        };

        let options = SendOptions::new_tron_send_options(trx_options);

        let result = tokio_test::block_on(TRX::send(
            "TCwwZeH6so1X4R5kcdbKqa4GWuzF53xPqG".to_string(),
            DEFAULT_ADDRESS.to_string(),
            BigNumber::from(1000000),
            Some(options),
            None,
        ));

        assert!(result.is_ok());
        let t = result.unwrap().clone();
        match t.clone().data {
            Some(TransactionRaw::Tron(tx)) => {
                let raw = &tx.raw_data.unwrap();
                assert_eq!(raw.contract.len(), 1);
                let c: kos_proto::tron::TriggerSmartContract =
                    kos_proto::unpack_from_option_any(&raw.contract.get(0).unwrap().parameter)
                        .unwrap();
                let data: String = c.data.iter().map(|b| format!("{:02X}", b)).collect();
                let owner_address = address::Address::from_bytes(&c.owner_address);
                let contract_address = address::Address::from_bytes(&c.contract_address);
                assert!(data.starts_with("A9059CBB"));
                assert_eq!(
                    owner_address.to_string(),
                    "TCwwZeH6so1X4R5kcdbKqa4GWuzF53xPqG".to_string()
                );
                assert_eq!(
                    contract_address.to_string(),
                    "TKk6DLX1xWRKHjDhHfdyQKefnP1WUppEXB".to_string()
                );
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_validate_bip44() {
        let default_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let v = vec![
            (0, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
            (1, "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK"),
            (2, "TYJPRrdB5APNeRs4R7fYZSwW3TcrTKw2gx"),
            (3, "TRhVWK5XEDkQBDevcdCWW7RW51aRncty4W"),
            (4, "TT2X2yyubp7qpAWYYNE5JQWBtoZ7ikQFsY"),
        ];

        for (index, expected_addr) in v {
            let path = TRX::get_path(&PathOptions::new(index)).unwrap();
            let kp = TRX::keypair_from_mnemonic(default_mnemonic, &path, None).unwrap();
            let addr = TRX::get_address_from_keypair(&kp).unwrap();

            assert_eq!(expected_addr, addr);
        }
    }

    #[test]
    fn test_validate_address_ok() {
        // valid addresses
        let list = [
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
            "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK",
            "TYJPRrdB5APNeRs4R7fYZSwW3TcrTKw2gx",
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        ];

        for addr in list {
            let result = TRX::validate_address(addr, None);
            assert!(result.is_ok());

            let result = result.unwrap();
            assert_eq!(result, true, "address: {}", addr);
        }
    }

    #[test]
    fn test_validate_address_invalid() {
        // invalid addresses
        let list = [
            "TuEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
            "TronEnergyioE1Z3ukeRv38sYkv5Jn55bL",
            "TronEnergyioNijNo8g3LF2ABKUAae6D2Z",
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH1",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        ];

        for addr in list {
            let result = TRX::validate_address(addr, None);
            assert!(result.is_ok());

            let result = result.unwrap();
            assert_eq!(result, false, "address: {}", addr);
        }
    }
}
