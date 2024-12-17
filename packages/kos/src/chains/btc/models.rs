use crate::chains::util::{private_key_from_vec, slice_from_vec};
use crate::chains::ChainError;
use crate::crypto::hash::sha256_digest;
use crate::crypto::secp256k1::{Secp256K1, Secp256k1Trait};
use std::error::Error;

#[derive(Debug, Clone)]
pub struct BTCTransaction {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl BTCTransaction {
    pub fn sign(&mut self, private_key: &[u8]) -> Result<(), ChainError> {
        let hash_type = 1; // SIGHASH_ALL

        let outputs = self.outputs.clone();
        let inputs_data: Vec<_> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                let script_pubkey = outputs[input.vout as usize].script_pubkey.clone();
                let hash = self.calculate_segwit_hash(i, &script_pubkey)?;
                Ok((hash, script_pubkey))
            })
            .collect::<Result<_, ChainError>>()?;

        for (input, (hash, _script_pubkey)) in self.inputs.iter_mut().zip(inputs_data) {
            let pvk_bytes = private_key_from_vec(private_key)?;
            let payload_bytes = slice_from_vec(&hash)?;

            let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;
            let mut der = Secp256K1::convert_to_der(&sig)?;

            der.push(hash_type as u8);

            let pbk = Secp256K1::private_to_public_compressed(&pvk_bytes)?;

            input.witness = vec![der, pbk.to_vec()];
            input.script_sig.clear();
        }

        Ok(())
    }

    fn calculate_segwit_hash(
        &self,
        input_index: usize,
        script_pubkey: &[u8],
    ) -> Result<[u8; 32], ChainError> {
        use crate::crypto::hash::sha256_digest;

        let mut hash_prevouts = Vec::new();
        let mut hash_sequence = Vec::new();

        for input in &self.inputs {
            hash_prevouts.extend(&input.txid);
            hash_prevouts.extend(&input.vout.to_le_bytes());
        }
        let hash_prevouts = sha256_digest(&sha256_digest(&hash_prevouts));

        for input in &self.inputs {
            hash_sequence.extend(&input.sequence.to_le_bytes());
        }
        let hash_sequence = sha256_digest(&sha256_digest(&hash_sequence));

        let input = &self.inputs[input_index];
        let mut input_data: Vec<u8> = Vec::new();
        input_data.extend(&input.txid);
        input_data.extend(&input.vout.to_le_bytes());
        input_data.extend(&(script_pubkey.len() as u64).to_le_bytes()); // Tamanho do script_pubkey
        input_data.extend(script_pubkey);
        input_data.extend(&input.sequence.to_le_bytes());

        let mut hash_outputs = Vec::new();
        for output in &self.outputs {
            hash_outputs.extend(&output.value.to_le_bytes());
            hash_outputs.extend(&(output.script_pubkey.len() as u64).to_le_bytes());
            hash_outputs.extend(&output.script_pubkey);
        }
        let hash_outputs = sha256_digest(&sha256_digest(&hash_outputs));

        let mut tx_hash_buffer = Vec::new();
        tx_hash_buffer.extend(&self.version.to_le_bytes());
        tx_hash_buffer.extend(&hash_prevouts);
        tx_hash_buffer.extend(&hash_sequence);
        tx_hash_buffer.extend(input_data);
        tx_hash_buffer.extend(&hash_outputs);
        tx_hash_buffer.extend(&self.lock_time.to_le_bytes());
        tx_hash_buffer.extend(&(1u32.to_le_bytes())); // hash type

        Ok(sha256_digest(&sha256_digest(&tx_hash_buffer)))
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self, ChainError> {
        let mut cursor = raw;

        let version = read_u32(&mut cursor)?;
        let input_count = read_varint(&mut cursor)?;
        let mut inputs = Vec::new();

        for _ in 0..input_count {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&cursor[..32]);
            cursor = &cursor[32..];

            let vout = read_u32(&mut cursor)?;
            let script_sig_len = read_varint(&mut cursor)?;
            let script_sig = cursor[..script_sig_len as usize].to_vec();
            cursor = &cursor[script_sig_len as usize..];

            let sequence = read_u32(&mut cursor)?;

            inputs.push(Input {
                txid,
                vout,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }

        let output_count = read_varint(&mut cursor)?;
        let mut outputs = Vec::new();

        for _ in 0..output_count {
            let value = read_u64(&mut cursor)?;
            let script_pubkey_len = read_varint(&mut cursor)?;
            let script_pubkey = cursor[..script_pubkey_len as usize].to_vec();
            cursor = &cursor[script_pubkey_len as usize..];

            outputs.push(Output {
                value,
                script_pubkey,
            });
        }

        let lock_time = read_u32(&mut cursor)?;

        Ok(Self {
            version,
            lock_time,
            inputs,
            outputs,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut raw_tx = Vec::new();

        raw_tx.extend(&self.version.to_le_bytes());

        let is_segwit = self.inputs.iter().any(|input| !input.witness.is_empty());

        if is_segwit {
            // Add SegWit marker and flag
            raw_tx.push(0x00); // Marker
            raw_tx.push(0x01); // Flag
        }

        raw_tx.push(self.inputs.len() as u8);
        for input in &self.inputs {
            raw_tx.extend(&input.txid);
            raw_tx.extend(&input.vout.to_le_bytes());
            raw_tx.push(input.script_sig.len() as u8);
            raw_tx.extend(&input.script_sig);
            raw_tx.extend(&input.sequence.to_le_bytes());
        }

        raw_tx.push(self.outputs.len() as u8);
        for output in &self.outputs {
            raw_tx.extend(&output.value.to_le_bytes());
            raw_tx.push(output.script_pubkey.len() as u8);
            raw_tx.extend(&output.script_pubkey);
        }

        if is_segwit {
            for input in &self.inputs {
                raw_tx.push(input.witness.len() as u8);
                for item in &input.witness {
                    raw_tx.push(item.len() as u8);
                    raw_tx.extend(item);
                }
            }
        }

        raw_tx.extend(&self.lock_time.to_le_bytes());

        raw_tx
    }
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32, ChainError> {
    if cursor.len() < 4 {
        return Err(ChainError::InvalidData("Insufficient bytes for u32".into()));
    }
    let value = u32::from_le_bytes(cursor[..4].try_into().unwrap());
    *cursor = &cursor[4..];
    Ok(value)
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, ChainError> {
    if cursor.len() < 8 {
        return Err(ChainError::InvalidData("Buffer underflow".into()));
    }
    let value = u64::from_le_bytes(cursor[..8].try_into().unwrap());
    *cursor = &cursor[8..];
    Ok(value)
}

fn read_varint(cursor: &mut &[u8]) -> Result<u64, ChainError> {
    if cursor.is_empty() {
        return Err(ChainError::InvalidData("Empty cursor for varint".into()));
    }

    let first = cursor[0];
    *cursor = &cursor[1..];

    match first {
        0xFF => {
            if cursor.len() < 8 {
                return Err(ChainError::InvalidData(
                    "Insufficient bytes for varint u64".into(),
                ));
            }
            let value = u64::from_le_bytes(cursor[..8].try_into().unwrap());
            *cursor = &cursor[8..];
            Ok(value)
        }
        0xFE => {
            if cursor.len() < 4 {
                return Err(ChainError::InvalidData(
                    "Insufficient bytes for varint u32".into(),
                ));
            }
            let value = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as u64;
            *cursor = &cursor[4..];
            Ok(value)
        }
        0xFD => {
            if cursor.len() < 2 {
                return Err(ChainError::InvalidData(
                    "Insufficient bytes for varint u16".into(),
                ));
            }
            let value = u16::from_le_bytes(cursor[..2].try_into().unwrap()) as u64;
            *cursor = &cursor[2..];
            Ok(value)
        }
        _ => Ok(first as u64),
    }
}
