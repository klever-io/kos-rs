use kos::crypto::bignum::U256;
use rlp::{DecoderError, Rlp, RlpStream};

#[derive(Debug, PartialEq)]
pub enum TransactionType {
    Legacy,
    Eip155,
}

pub struct EthereumTransaction {
    pub transaction_type: TransactionType,
    pub nonce: U256,
    pub to: Option<Vec<u8>>, // Ethereum address (Option for contract creation)
    pub gas: U256,
    pub gas_price: Option<U256>,
    pub value: U256,
    pub data: Vec<u8>,
    pub chain_id: Option<u64>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub signature: Option<[u8; 65]>,
}

impl EthereumTransaction {
    #[allow(clippy::unnecessary_unwrap)]
    pub fn decode(rlp_data: &[u8]) -> Result<Self, DecoderError> {
        let rlp = Rlp::new(rlp_data);

        let tx_result = self::EthereumTransaction::decode_legacy(&rlp);
        if tx_result.is_ok() {
            return Ok(tx_result.unwrap());
        }

        let tx_result = self::EthereumTransaction::decode_eip_envelope(rlp);
        if tx_result.is_ok() {
            return Ok(tx_result.unwrap());
        }

        let rlp = Rlp::new(&rlp_data[2..]);
        self::EthereumTransaction::decode_eip155(rlp)
    }

    pub fn encode_eip1559(&self) -> Result<RlpStream, DecoderError> {
        let mut rlp = RlpStream::new();
        let list_size = if self.signature.is_some() { 12 } else { 9 };
        rlp.begin_list(list_size);
        rlp.append(&self.chain_id.unwrap_or(0));
        rlp.append(&self.nonce);
        rlp.append(
            &self
                .max_priority_fee_per_gas
                .clone()
                .unwrap_or(U256([0; 32])),
        );
        let gas_price = self.max_fee_per_gas.clone().unwrap_or(U256([0; 32]));

        rlp.append(&gas_price);
        rlp.append(&self.gas);
        if let Some(to) = &self.to {
            rlp.append(to);
        } else {
            rlp.append(&"");
        }
        rlp.append(&self.value);
        rlp.append(&self.data);

        rlp.begin_list(0);

        if self.signature.is_some() {
            let sig = self.signature.unwrap_or([0; 65]);
            let mut r = U256([0; 32]);
            r.0.copy_from_slice(&sig[..32]);
            let mut s = U256([0; 32]);
            s.0.copy_from_slice(&sig[32..64]);
            let v = sig[64] as u64;
            rlp.append(&v);
            rlp.append(&r);
            rlp.append(&s);
        }
        Ok(rlp)
    }

    pub fn encode_legacy(&self) -> Result<RlpStream, DecoderError> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9);

        rlp.append(&self.nonce);
        rlp.append(&self.gas_price.clone().unwrap_or(U256([0; 32])));
        rlp.append(&self.gas);

        if let Some(to_addr) = &self.to {
            rlp.append(&to_addr.as_slice());
        } else {
            rlp.append(&"");
        }

        rlp.append(&self.value);
        rlp.append(&self.data);

        // Handle signature fields (v, r, s) - always present in legacy transactions
        if let Some(sig) = &self.signature {
            if sig.len() != 65 {
                return Err(DecoderError::Custom("Invalid signature length"));
            }

            // Parse r and s from signature (first 32 bytes = r, next 32 bytes = s)
            let mut r_bytes = [0u8; 32];
            let mut s_bytes = [0u8; 32];
            r_bytes.copy_from_slice(&sig[..32]);
            s_bytes.copy_from_slice(&sig[32..64]);

            let r = U256(r_bytes);
            let s = U256(s_bytes);

            // Calculate v based on chain_id (EIP-155) or legacy format
            let v = if let Some(chain_id) = self.chain_id {
                // EIP-155: v = chain_id * 2 + 35 + recovery_id
                chain_id * 2 + 35 + (sig[64] as u64)
            } else {
                // Pre-EIP-155: v = 27 + recovery_id
                27 + (sig[64] as u64)
            };

            rlp.append(&v);
            rlp.append(&r);
            rlp.append(&s);
        } else {
            // Unsigned transaction - used for signing
            if let Some(chain_id) = self.chain_id {
                // EIP-155 unsigned transaction
                rlp.append(&chain_id);
                rlp.append(&U256([0; 32]));
                rlp.append(&U256([0; 32]));
            } else {
                // Pre-EIP-155 unsigned transaction
                rlp.append(&U256([0; 32]));
                rlp.append(&U256([0; 32]));
                rlp.append(&U256([0; 32]));
            }
        }

        Ok(rlp)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DecoderError> {
        match self.transaction_type {
            TransactionType::Legacy => {
                let stream = self.encode_legacy()?;
                Ok(stream.out().to_vec())
            }

            TransactionType::Eip155 => {
                let stream = self.encode_eip1559()?;
                Ok([&[2], stream.as_raw()].concat())
            }
        }
    }

    pub fn decode_legacy(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(EthereumTransaction {
            transaction_type: TransactionType::Legacy,
            nonce: rlp.val_at(0)?,
            gas_price: Some(rlp.val_at(1)?),
            gas: rlp.val_at(2)?,
            to: Some(rlp.val_at(3)?),
            value: rlp.val_at(4)?,
            data: rlp.val_at(5)?,
            chain_id: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            signature: None,
        })
    }

    pub fn decode_eip155(rlp: Rlp) -> Result<Self, DecoderError> {
        Ok(EthereumTransaction {
            transaction_type: TransactionType::Eip155,
            chain_id: Some(rlp.val_at(0)?),
            nonce: rlp.val_at(1)?,
            max_priority_fee_per_gas: Some(rlp.val_at(2)?),
            max_fee_per_gas: Some(rlp.val_at(3)?),
            gas: rlp.val_at(4)?,
            to: Some(rlp.val_at(5)?), // Convert to Option
            value: rlp.val_at(6)?,
            data: rlp.val_at(7)?,
            signature: None,
            gas_price: None,
        })
    }

    pub fn decode_eip_envelope(rlp: Rlp) -> Result<Self, DecoderError> {
        let mut string_tx: String = rlp.to_string();
        string_tx = string_tx[1..string_tx.len() - 1].to_string();
        if string_tx.starts_with("0x") {
            string_tx = string_tx[2..].to_string();
        }

        let mut byte_tx = hex::decode(string_tx).map_err(|_| DecoderError::RlpExpectedToBeData)?;
        if byte_tx[0] == 2 {
            byte_tx.remove(0);
        }

        let rlp = Rlp::new(&byte_tx);
        EthereumTransaction::decode_eip155(rlp)
    }
}
