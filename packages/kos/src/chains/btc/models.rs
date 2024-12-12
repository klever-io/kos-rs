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
    txid: [u8; 32],
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Debug, Clone)]
pub struct Output {
    value: u64,
    script_pubkey: Vec<u8>,
}

impl BTCTransaction {
    pub fn sign(&mut self, private_key: Vec<u8>) -> Result<(), ChainError> {
        let mut tx = self.clone();
        let hash_type = 1;

        for i in 0..tx.inputs.len() {
            let input = &tx.inputs[i];
            let script_sig = input.script_sig.clone();
            let script_pubkey = &tx.outputs[input.vout as usize].script_pubkey;
            let mut script = script_sig.clone();
            script.extend_from_slice(&script_pubkey);
            let hash = sha256_digest(&sha256_digest(&script));

            let mut pvk_bytes = private_key_from_vec(&private_key)?;
            let payload_bytes = slice_from_vec(&hash.to_vec())?;
            let sig = Secp256K1::sign(&payload_bytes, &pvk_bytes)?;

            pvk_bytes.fill(0);

            let signature = sig.to_vec();
            let mut signature = signature.to_vec();
            signature.push(hash_type as u8);
            let mut script_sig = vec![signature.len() as u8];
            script_sig.extend_from_slice(&signature);
            tx.inputs[i].script_sig = script_sig;
        }
        *self = tx;
        Ok(())
    }

    pub fn from_raw(raw: Vec<u8>) -> Result<Self, ChainError> {
        let mut cursor = &raw[..];

        let version = read_u32(&mut cursor).unwrap();

        let input_count = read_varint(&mut cursor).unwrap();
        let mut inputs = Vec::new();

        for _ in 0..input_count {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&cursor[..32]);
            cursor = &cursor[32..];

            let vout = read_u32(&mut cursor).unwrap();

            let script_sig_len = read_varint(&mut cursor).unwrap();
            let script_sig = cursor[..script_sig_len as usize].to_vec();
            cursor = &cursor[script_sig_len as usize..];

            let sequence = read_u32(&mut cursor).unwrap();

            inputs.push(Input {
                txid,
                vout,
                script_sig,
                sequence,
            });
        }

        let output_count = read_varint(&mut cursor).unwrap();
        let mut outputs = Vec::new();

        for _ in 0..output_count {
            let value = read_u64(&mut cursor).unwrap();

            let script_pubkey_len = read_varint(&mut cursor).unwrap();
            let script_pubkey = cursor[..script_pubkey_len as usize].to_vec();
            cursor = &cursor[script_pubkey_len as usize..];

            outputs.push(Output {
                value,
                script_pubkey,
            });
        }

        let lock_time = read_u32(&mut cursor).unwrap();

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

        raw_tx.extend(&self.lock_time.to_le_bytes());

        raw_tx
    }
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32, Box<dyn Error>> {
    if cursor.len() < 4 {
        return Err("Buffer underflow".into());
    }
    let value = u32::from_le_bytes(cursor[..4].try_into().unwrap());
    *cursor = &cursor[4..];
    Ok(value)
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, Box<dyn Error>> {
    if cursor.len() < 8 {
        return Err("Buffer underflow".into());
    }
    let value = u64::from_le_bytes(cursor[..8].try_into().unwrap());
    *cursor = &cursor[8..];
    Ok(value)
}

fn read_varint(cursor: &mut &[u8]) -> Result<u64, Box<dyn Error>> {
    if cursor.is_empty() {
        return Err("Buffer underflow".into());
    }

    let first = cursor[0];
    *cursor = &cursor[1..];

    match first {
        0xFF => {
            if cursor.len() < 8 {
                return Err("Buffer underflow".into());
            }
            let value = u64::from_le_bytes(cursor[..8].try_into().unwrap());
            *cursor = &cursor[8..];
            Ok(value)
        }
        0xFE => {
            if cursor.len() < 4 {
                return Err("Buffer underflow".into());
            }
            let value = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as u64;
            *cursor = &cursor[4..];
            Ok(value)
        }
        0xFD => {
            if cursor.len() < 2 {
                return Err("Buffer underflow".into());
            }
            let value = u16::from_le_bytes(cursor[..2].try_into().unwrap()) as u64;
            *cursor = &cursor[2..];
            Ok(value)
        }
        _ => Ok(first as u64),
    }
}
