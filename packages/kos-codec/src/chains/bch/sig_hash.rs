use bitcoin::hashes::{sha256, Hash};
use byteorder::{LittleEndian, WriteBytesExt};
use kos::chains::ChainError;
use std::io::Write;

/// Signs all of the outputs
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign none of the outputs so that they may be spent anywhere
const SIGHASH_NONE: u8 = 0x02;
/// Sign only the output paired with the the input
const SIGHASH_SINGLE: u8 = 0x03;
/// Sign only the input so others may inputs to the transaction
const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// Bitcoin Cash / SV sighash flag for use on outputs after the fork
pub const SIGHASH_FORKID: u8 = 0x40;

const OUT_PINT_SIZE: usize = 36;

/// Cache for sighash intermediate values to avoid quadratic hashing
///
/// This is only valid for one transaction, but may be used for multiple signatures.
pub struct SigHashCache {
    hash_prevouts: Option<sha256::Hash>,
    hash_sequence: Option<sha256::Hash>,
    hash_outputs: Option<sha256::Hash>,
}

impl SigHashCache {
    /// Creates a new cache
    pub fn new() -> SigHashCache {
        SigHashCache {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
}

/// Generates a transaction digest for signing using BIP-143
///
/// This is to be used for all tranasctions after the August 2017 fork.
/// It fixing quadratic hashing and includes the satoshis spent in the hash.
pub fn bip143_sighash(
    tx: &bitcoin::Transaction,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<sha256::Hash, ChainError> {
    if n_input >= tx.input.len() {
        return Err(ChainError::DecodeRawTx);
    }

    let mut s = Vec::with_capacity(tx.total_size());
    let base_type = sighash_type & 31;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;

    // 1. Serialize version
    s.write_u32::<LittleEndian>(tx.version.0 as u32)
        .map_err(|_| ChainError::DecodeRawTx)?;

    // 2. Serialize hash of prevouts
    if !anyone_can_pay {
        if cache.hash_prevouts.is_none() {
            let mut prev_outputs = Vec::with_capacity(OUT_PINT_SIZE * tx.input.len());
            for input in tx.input.iter() {
                prev_outputs.extend_from_slice(
                    bitcoin::consensus::serialize(&input.previous_output).as_ref(),
                );
            }
            cache.hash_prevouts = Some(sha256d(&prev_outputs));
        }

        let hash_prevouts_to_serialize = cache.hash_prevouts.ok_or(ChainError::DecodeRawTx)?;

        s.write(&hash_prevouts_to_serialize.to_byte_array())
            .map_err(|_| ChainError::DecodeRawTx)?;
    } else {
        s.write(&[0; 32]).map_err(|_| ChainError::DecodeRawTx)?;
    }

    // 3. Serialize hash of sequences
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_sequence.is_none() {
            let mut sequences = Vec::with_capacity(4 * tx.input.len());
            for tx_in in tx.input.iter() {
                sequences
                    .write_u32::<LittleEndian>(tx_in.sequence.0)
                    .map_err(|_| ChainError::DecodeRawTx)?;
            }
            cache.hash_sequence = Some(sha256d(&sequences));
        }
        let hash_sequence_to_serialize = cache.hash_sequence.ok_or(ChainError::DecodeRawTx)?;

        s.write(&hash_sequence_to_serialize.to_byte_array())
            .map_err(|_| ChainError::DecodeRawTx)?;
    } else {
        s.write(&[0; 32]).map_err(|_| ChainError::DecodeRawTx)?;
    }

    // 4. Serialize prev output
    let prev_output_serialize = bitcoin::consensus::serialize(&tx.input[n_input].previous_output);
    s.write(&prev_output_serialize)
        .map_err(|_| ChainError::DecodeRawTx)?;

    // 5. Serialize input script
    var_int_write(script_code.len() as u64, &mut s).map_err(|_| ChainError::DecodeRawTx)?;
    s.write(script_code).map_err(|_| ChainError::DecodeRawTx)?;

    // 6. Serialize satoshis
    s.write_i64::<LittleEndian>(satoshis)
        .map_err(|_| ChainError::DecodeRawTx)?;

    // 7. Serialize sequence
    s.write_u32::<LittleEndian>(tx.input[n_input].sequence.0)
        .map_err(|_| ChainError::DecodeRawTx)?;

    // 8. Serialize hash of outputs
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_outputs.is_none() {
            let mut size = 0;
            for tx_out in tx.output.iter() {
                size += tx_out.size();
            }
            let mut outputs = Vec::with_capacity(size);
            for tx_out in tx.output.iter() {
                outputs.extend_from_slice(bitcoin::consensus::serialize(&tx_out).as_ref());
            }
            cache.hash_outputs = Some(sha256d(&outputs));
        }

        let hash_outputs_to_serialize = cache.hash_outputs.ok_or(ChainError::DecodeRawTx)?;

        let hash_outputs =
            bitcoin::consensus::serialize(&hash_outputs_to_serialize.as_byte_array());

        s.write(&hash_outputs)
            .map_err(|_| ChainError::DecodeRawTx)?;
    } else if base_type == SIGHASH_SINGLE && n_input < tx.output.len() {
        let mut outputs = Vec::with_capacity(tx.output[n_input].size());
        outputs.extend_from_slice(bitcoin::consensus::serialize(&tx.output[n_input]).as_ref());
        s.write(&sha256d(&outputs).to_byte_array())
            .map_err(|_| ChainError::DecodeRawTx)?;
    } else {
        s.write(&[0; 32]).map_err(|_| ChainError::DecodeRawTx)?;
    }

    // 9. Serialize lock_time
    s.write_u32::<LittleEndian>(tx.lock_time.to_consensus_u32())
        .map_err(|_| ChainError::DecodeRawTx)?;

    // 10. Serialize hash type
    s.write_u32::<LittleEndian>(sighash_type as u32)
        .map_err(|_| ChainError::DecodeRawTx)?;

    Ok(sha256d(&s))
}

/// Hashes a data array twice using SHA256
pub fn sha256d(data: &[u8]) -> sha256::Hash {
    let sha256 = sha256::Hash::hash(data);
    let sha256 = sha256::Hash::hash(sha256.as_ref());
    sha256
}

/// Writes the var int to bytes
pub fn var_int_write(n: u64, writer: &mut dyn Write) -> std::io::Result<()> {
    if n <= 252 {
        writer.write_u8(n as u8)?;
    } else if n <= 0xffff {
        writer.write_u8(0xfd)?;
        writer.write_u16::<LittleEndian>(n as u16)?;
    } else if n <= 0xffffffff {
        writer.write_u8(0xfe)?;
        writer.write_u32::<LittleEndian>(n as u32)?;
    } else {
        writer.write_u8(0xff)?;
        writer.write_u64::<LittleEndian>(n)?;
    }
    Ok(())
}
