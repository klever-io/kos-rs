mod models;

use crate::chains::{Chain, ChainError, Transaction, TxInfo, TxType};
use crate::crypto::bip32;
use crate::crypto::ed25519::{Ed25519, Ed25519Trait};
use crate::crypto::hash::{blake2b_digest, keccak256_digest};
use crate::protos::generated::klv::proto;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bech32::{u5, Variant};

use crate::chains::util::private_key_from_vec;
use crate::crypto::base64::simple_base64_encode;
use crate::crypto::bignum::U256;
use prost::Message;

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
        let raw_tx = tx.raw_data;

        // Parse [] empty arrays to [""] to avoid decoding errors
        let json = String::from_utf8(raw_tx.clone())?;
        let parsed = json.replace("[]", "[\"\"]").as_bytes().to_vec();

        let mut js_tx: models::Transaction = tiny_json_rs::decode(String::from_utf8(parsed)?)?;

        let klv_tx = proto::Transaction::try_from(js_tx.clone())
            .map_err(|_| ChainError::ProtoDecodeError)?;

        let raw_data = klv_tx
            .raw_data
            .clone()
            .ok_or(ChainError::ProtoDecodeError)?;
        let mut tx_raw = Vec::with_capacity(raw_data.encoded_len());
        raw_data.encode(&mut tx_raw)?;
        let result_buffer = blake2b_digest(&tx_raw);

        let sig = self.sign_raw(private_key, result_buffer.to_vec())?;

        js_tx.signature = Some(Vec::from([simple_base64_encode(&sig)]));

        tx.raw_data = tiny_json_rs::encode(js_tx).into_bytes();
        tx.tx_hash = result_buffer.to_vec();
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

    fn get_tx_info(&self, raw_tx: Vec<u8>) -> Result<TxInfo, ChainError> {
        let js_tx: models::Transaction = tiny_json_rs::decode(String::from_utf8(raw_tx)?)?;
        let tx = proto::Transaction::try_from(js_tx).map_err(|_| ChainError::ProtoDecodeError)?;
        let raw = tx.raw_data.ok_or(ChainError::ProtoDecodeError)?;

        if raw.contract.len() != 1 {
            return Err(ChainError::ProtoDecodeError);
        }

        let c_type: proto::tx_contract::ContractType =
            proto::tx_contract::ContractType::try_from(raw.contract[0].r#type)
                .map_err(|_| ChainError::ProtoDecodeError)?;
        match c_type {
            proto::tx_contract::ContractType::TransferContractType => {
                let value = raw.contract[0].clone().parameter.unwrap().value;
                let tc = proto::TransferContract::decode(value.as_slice())
                    .map_err(|_| ChainError::ProtoDecodeError)?;
                let sender = self.get_address(raw.sender)?;
                let receiver = self.get_address(tc.to_address)?;
                let value = U256::from_i64(tc.amount).to_f64(self.get_decimals());

                Ok(TxInfo {
                    sender,
                    receiver,
                    value,
                    tx_type: TxType::Transfer,
                })
            }
            _ => Ok(TxInfo {
                sender: String::new(),
                receiver: String::new(),
                value: 0.0,
                tx_type: TxType::Unknown,
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::chains::Chain;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

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

    #[test]
    fn test_sign_tx() {
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();

        let raw_tx = hex::decode(
            "7b2252617744617461223a7b224e6f6e6365223a3837312c2253656e646572223a226e506832763367457a636d41684b4c783630764d41734e65384a5871716f5a47695a30504e51434c2b55303d222c22436f6e7472616374223a5b7b22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6e7472616374222c2276616c7565223a224369417633486c46453731646170613948454e704a454b4671656e7468417a32306b67436c76776e46753076635249714d48686b59574d784e3259354e54686b4d6d566c4e54497a595449794d4459794d4459354f5451314f54646a4d544e6b4f444d785a574d3347416f3d227d7d5d2c224b417070466565223a313030303030302c2242616e647769647468466565223a323030303030302c2256657273696f6e223a312c22436861696e4944223a224d544134227d7d",
        )
        .unwrap();

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let result_tx = crate::chains::klv::KLV {}.sign_tx(pvk, tx).unwrap();
        assert_eq!(
            result_tx.tx_hash,
            hex::decode("0f47f28830f7aa9607a7a462b267003f94b4ef2c5c28ac8763cfc68e8fe10915")
                .unwrap()
        )
    }

    #[test]
    fn test_sign_tx_2() {
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();

        let raw_tx = hex::decode(
            "7b2252617744617461223a7b224e6f6e6365223a3536392c2253656e646572223a2253715146557a4c44745a4e7a58657865592b2b424d56483547544b4c444d53786f3732476f52716a5a7a303d222c22436f6e7472616374223a5b7b2254797065223a392c22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e436c61696d436f6e7472616374227d7d5d2c224b417070466565223a313030303030302c2242616e647769647468466565223a323030303030302c2256657273696f6e223a312c22436861696e4944223a224d544134227d7d",
        )
        .unwrap();

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let result_tx = crate::chains::klv::KLV {}.sign_tx(pvk, tx).unwrap();

        assert_eq!(
            result_tx.tx_hash,
            hex::decode("a4f4768ef619999241cb6c81fed8affc8dbaaa32dd4ded674273c8b6f06ddf93")
                .unwrap()
        );
    }

    #[test]
    fn test_sign_tx_3() {
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();

        let json = r#"{"Signature":[],"RawData":{"Contract":[{"Parameter":{"value":"CiAErjVpczGsXwth+8y37LCGSr5O6tPlR9nduy2Np+8wyBIDS0xWGMCEPQ==","type_url":"type.googleapis.com\/proto.TransferContract"}}],"Nonce":580,"BandwidthFee":2000000,"Data":[""],"ChainID":"MTA4","Version":1,"Sender":"SqQFUzLDtZNzXexeY++BMVH5GTKLDMSxo72GoRqjZz0=","KAppFee":1000000}}"#;

        let raw_tx = json.as_bytes().to_vec();

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let result_tx = crate::chains::klv::KLV {}.sign_tx(pvk, tx).unwrap();

        assert_eq!(
            result_tx.tx_hash,
            hex::decode("cb2741a67bb2e84f21ac892c9b6577446955debe9c9ef40c1799d212e617a55f")
                .unwrap()
        );
    }

    #[test]
    fn test_sign_tx_4() {
        let pvk = hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
            .unwrap();

        let json = r#"{"RawData":{"Sender":"UMjR49Dkn+HleedQY88TSjXXJhtbDpX7f7QVF/Dcqos=","Contract":[{"Type":63,"Parameter":{"type_url":"type.googleapis.com/proto.SmartContract","value":"EiAAAAAAAAAAAAUAIPnuq04LIuz1ew83LbqEVgLiyNyybBoRCghGUkctMlZCVRIFCIDh6xc="}}],"Data":["c3Rha2VGYXJt"],"KAppFee":2000000,"BandwidthFee":4622449,"Version":1,"ChainID":"MTAwMDAx"}}"#;

        let raw_tx = json.as_bytes().to_vec();

        let tx = crate::chains::Transaction {
            raw_data: raw_tx,
            tx_hash: Vec::new(),
            signature: Vec::new(),
            options: None,
        };

        let result_tx = crate::chains::klv::KLV {}.sign_tx(pvk, tx).unwrap();

        assert_eq!(
            result_tx.tx_hash,
            hex::decode("50fce82cb3f4bf851d86fd594133b13e891d1f565958b0a95b11ce47f2179926")
                .unwrap()
        );
    }

    #[test]
    fn test_decode_klv_tx() {
        let raw_tx = hex::decode(
            "7b225261774\
        4617461223a7b224e6f6e6365223a322c2253656e646572223a2231427\
        673447457583848784162506664437742686b6956767378446637354e7a\
        4d4f6c44727357377034633d222c22436f6e7472616374223a5b7b22506\
        172616d65746572223a7b22747970655f75726c223a22747970652e676f\
        6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6\
        e7472616374222c2276616c7565223a224369446653574f374e61687538\
        74717056506b4d547645324a6a4649385752702f4d62452f326c702b385\
        06f37786742227d7d5d2c224b417070466565223a3530303030302c2242\
        616e647769647468466565223a313030303030302c2256657273696f6e2\
        23a312c22436861696e4944223a224d544134227d7d",
        )
        .unwrap();

        let tx_info = crate::chains::klv::KLV {}.get_tx_info(raw_tx).unwrap();
        assert_eq!(
            tx_info.sender,
            "klv16sd7crk4jlc8csrv7lwskqrpjgjklvcsmlhexuesa9p6a3dm57rs5vh0hq"
        );
    }
}
