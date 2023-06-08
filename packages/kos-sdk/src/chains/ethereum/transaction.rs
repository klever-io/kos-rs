use super::address::Address;

use kos_types::error::Error;

use ethereum_types::U256;
use rlp::RlpStream;
use secp256k1::ecdsa::RecoverableSignature;

#[derive(Clone, Debug, PartialEq)]
pub enum TransactionType {
    Legacy,
    EIP1559,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Transaction {
    pub transaction_type: Option<TransactionType>,
    pub nonce: U256,
    pub to: Option<Address>,
    pub gas: U256,
    pub gas_price: Option<U256>,
    pub value: U256,
    pub data: Vec<u8>,
    pub chain_id: Option<u64>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub signature: Option<RecoverableSignature>,
}

impl Transaction {
    fn rlp_append_legacy(&self, stream: &mut RlpStream) {
        stream.append(&self.nonce);
        stream.append(&self.gas_price.unwrap_or_default());
        stream.append(&self.gas);
        if let Some(to) = self.to {
            stream.append(&to.as_bytes());
        } else {
            stream.append(&"");
        }
        stream.append(&self.value);
        stream.append(&self.data);
    }

    fn encode_legacy(&self) -> RlpStream {
        let mut stream = RlpStream::new();
        stream.begin_list(9);

        self.rlp_append_legacy(&mut stream);

        if let Some(signature) = self.signature {
            self.rlp_append_signature(&mut stream, signature);
        } else {
            stream.append(&self.chain_id.unwrap_or(0));
            stream.append(&0u8);
            stream.append(&0u8);
        };

        stream
    }

    fn encode_eip1559_payload(&self) -> RlpStream {
        let mut stream = RlpStream::new();

        let list_size = if self.signature.is_some() { 12 } else { 9 };
        stream.begin_list(list_size);

        // append chain_id. from EIP-2930: chainId is defined to be an integer of arbitrary size.
        stream.append(&self.chain_id.unwrap_or(0));

        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas.unwrap_or_default());

        let gas_price = self.max_fee_per_gas.or(self.gas_price).unwrap_or_default();
        stream.append(&gas_price);

        stream.append(&self.gas);
        if let Some(to) = self.to {
            stream.append(&to.as_bytes());
        } else {
            stream.append(&"");
        }
        stream.append(&self.value);
        stream.append(&self.data);

        self.rlp_append_access_list(&mut stream);

        if let Some(signature) = self.signature {
            self.rlp_append_signature(&mut stream, signature);
        }

        stream
    }

    fn rlp_append_access_list(&self, stream: &mut RlpStream) {
        stream.begin_list(0);
        // todo!(access_list)
    }

    fn rlp_append_signature(&self, stream: &mut RlpStream, signature: RecoverableSignature) {
        // Deconstruct the signature into r, s, and v
        let (rec_id, raw_sig) = signature.serialize_compact();
        let v = self.rlp_adjust_v_value(rec_id.to_i32());
        let r = &raw_sig[0..32];
        let s = &raw_sig[32..64];
        stream.append(&v);
        stream.append(&U256::from_big_endian(r));
        stream.append(&U256::from_big_endian(s));
    }

    fn rlp_adjust_v_value(&self, v: i32) -> u64 {
        match self.transaction_type {
            Some(TransactionType::Legacy) | None => {
                let chain_id = self.chain_id.unwrap_or(0);
                chain_id * 2 + 35 + (v as u64)
            }
            _ => v as u64,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self.transaction_type {
            Some(TransactionType::Legacy) | None => {
                let stream = self.encode_legacy();
                Ok(stream.out().to_vec())
            }

            Some(TransactionType::EIP1559) => {
                let stream = self.encode_eip1559_payload();
                Ok([&[2], stream.as_raw()].concat())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::ethereum::address::Address;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    #[test]
    fn test_encode_legacy() {
        let tx = Transaction {
            transaction_type: Some(TransactionType::Legacy),
            nonce: U256::from_dec_str("691").unwrap(),
            to: Some(Address::try_from("0x4592D8f8D7B001e72Cb26A73e4Fa1806a51aC79d").unwrap()),
            gas: U256::from(21000),
            gas_price: Some(U256::from_dec_str("2000000000").unwrap()),
            value: U256::from_dec_str("1000000000000000000").unwrap(),
            data: Vec::new(),
            chain_id: Some(4),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            signature: Some(
                RecoverableSignature::from_compact(
                    &hex::decode("699ff162205967ccbabae13e07cdd4284258d46ec1051a70a51be51ec2bc69f34e6944d508244ea54a62ebf9a72683eeadacb73ad7c373ee542f1998147b220e").unwrap(), 
                    RecoveryId::from_i32(0).unwrap(),
                ).unwrap(),
            )
        };

        let raw = tx.encode().unwrap();
        let expected = hex::decode("f86d8202b38477359400825208944592d8f8d7b001e72cb26a73e4fa1806a51ac79d880de0b6b3a7640000802ba0699ff162205967ccbabae13e07cdd4284258d46ec1051a70a51be51ec2bc69f3a04e6944d508244ea54a62ebf9a72683eeadacb73ad7c373ee542f1998147b220e");

        assert_eq!(raw, expected.unwrap());
    }

    #[test]
    fn test_encode_eip1559() {
        let tx = Transaction {
            transaction_type: Some(TransactionType::EIP1559),
            nonce: U256::from_dec_str("241").unwrap(),
            to: Some(Address::try_from("0xe0e5d2B4EDcC473b988b44b4d13c3972cb6694cb").unwrap()),
            gas: U256::from(21000),
            gas_price: None,
            value: U256::from_dec_str("138078072511761950").unwrap(),
            data: Vec::new(),
            chain_id: Some(1),
            max_fee_per_gas: Some(U256::from_dec_str("91097072255").unwrap()),
            max_priority_fee_per_gas: Some(U256::from_dec_str("1000000000").unwrap()),
            signature: Some(
                RecoverableSignature::from_compact(
                    &hex::decode("7eb3335f4fd4de25ec3452c08882f28fb098b2eaa37a332941f918d869f5c2ad59b9d4aa997c7fa34f1b167f98a12432bb1a4a35660d723a9c19bb76b4cd025d").unwrap(), 
                    RecoveryId::from_i32(1).unwrap(),
                ).unwrap(),
            )
        };

        let raw = tx.encode().unwrap();
        let expected = hex::decode("02f8740181f1843b9aca00851535cf027f82520894e0e5d2b4edcc473b988b44b4d13c3972cb6694cb8801ea8d467f558e1e80c001a07eb3335f4fd4de25ec3452c08882f28fb098b2eaa37a332941f918d869f5c2ada059b9d4aa997c7fa34f1b167f98a12432bb1a4a35660d723a9c19bb76b4cd025d");

        assert_eq!(raw, expected.unwrap());
    }
}
