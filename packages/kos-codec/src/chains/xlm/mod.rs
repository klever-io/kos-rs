use base64::{engine::general_purpose, Engine as _};
use kos::chains::{ChainError, Transaction};
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    BytesM, DecoratedSignature, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
    WriteXdr,
};

const NETWORK_ID: [u8; 32] = [
    206, 224, 48, 45, 89, 132, 77, 50, 189, 202, 145, 92, 130, 3, 221, 68, 179, 63, 251, 126, 221,
    203, 5, 30, 163, 122, 173, 223, 40, 236, 212, 114,
];

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    // Parse the transaction from raw_data (expected to be XDR base64)
    let raw_data_str = String::from_utf8(transaction.raw_data.clone())
        .map_err(|_| ChainError::InvalidData("Invalid UTF-8 in raw_data".to_string()))?;

    // Decode the base64 first, then parse XDR
    let xdr_bytes = general_purpose::STANDARD
        .decode(&raw_data_str)
        .map_err(|e| ChainError::InvalidData(format!("Failed to decode base64: {}", e)))?;

    let tx_envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
        .map_err(|e| ChainError::InvalidData(format!("Failed to parse XDR: {}", e)))?;

    // Compute the transaction hash for signing using Stellar's hash method
    // In Stellar, the hash is SHA-256(network_id + transaction_envelope_xdr)
    // Get the transaction part without signatures for hashing
    let tx_hash = match &tx_envelope {
        TransactionEnvelope::TxV0(v0_env) => {
            let tx_xdr = v0_env.tx.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&NETWORK_ID);
            hasher.update(b"ENVELOPE_TYPE_TX_V0");
            hasher.update(&tx_xdr);
            hasher.finalize()
        }
        TransactionEnvelope::Tx(v1_env) => {
            let tx_xdr = v1_env.tx.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&NETWORK_ID);
            hasher.update(b"ENVELOPE_TYPE_TX");
            hasher.update(&tx_xdr);
            hasher.finalize()
        }
        TransactionEnvelope::TxFeeBump(fee_bump_env) => {
            let tx_xdr = fee_bump_env.tx.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&NETWORK_ID);
            hasher.update(b"ENVELOPE_TYPE_TX_FEE_BUMP");
            hasher.update(&tx_xdr);
            hasher.finalize()
        }
    };

    // Set the transaction hash to be signed
    transaction.tx_hash = tx_hash.to_vec();

    Ok(transaction)
}

pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    // Parse the original transaction from raw_data
    let raw_data_str = String::from_utf8(transaction.raw_data.clone())
        .map_err(|_| ChainError::InvalidData("Invalid UTF-8 in raw_data".to_string()))?;

    // Decode the base64 first, then parse XDR
    let xdr_bytes = general_purpose::STANDARD
        .decode(&raw_data_str)
        .map_err(|e| ChainError::InvalidData(format!("Failed to decode base64: {}", e)))?;

    let mut tx_envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
        .map_err(|e| ChainError::InvalidData(format!("Failed to parse XDR: {}", e)))?;

    // Create a decorated signature from the signature bytes
    if transaction.signature.len() != 64 {
        return Err(ChainError::InvalidSignature);
    }

    let signature_bytes: [u8; 64] = transaction
        .signature
        .clone()
        .try_into()
        .map_err(|_| ChainError::InvalidSignature)?;

    // Create signature using the proper stellar-xdr API
    let signature = Signature::from(
        BytesM::try_from(signature_bytes.to_vec()).map_err(|_| ChainError::InvalidSignature)?,
    );
    let decorated_signature = DecoratedSignature {
        hint: SignatureHint([0; 4]), // Hint can be empty or derived from public key
        signature,
    };

    // Add the signature to the appropriate envelope type
    match &mut tx_envelope {
        TransactionEnvelope::TxV0(ref mut v0_env) => {
            // Create a new signatures vector with the decorated signature
            let mut sigs = v0_env.signatures.clone().into_vec();
            sigs.push(decorated_signature);
            v0_env.signatures = sigs
                .try_into()
                .map_err(|_| ChainError::InvalidData("Too many signatures".to_string()))?;
        }
        TransactionEnvelope::Tx(ref mut v1_env) => {
            // Create a new signatures vector with the decorated signature
            let mut sigs = v1_env.signatures.clone().into_vec();
            sigs.push(decorated_signature);
            v1_env.signatures = sigs
                .try_into()
                .map_err(|_| ChainError::InvalidData("Too many signatures".to_string()))?;
        }
        TransactionEnvelope::TxFeeBump(ref mut fee_bump_env) => {
            // Create a new signatures vector with the decorated signature
            let mut sigs = fee_bump_env.signatures.clone().into_vec();
            sigs.push(decorated_signature);
            fee_bump_env.signatures = sigs
                .try_into()
                .map_err(|_| ChainError::InvalidData("Too many signatures".to_string()))?;
        }
    }

    // Encode the signed transaction back to XDR and then base64 for broadcast
    let signed_xdr_bytes = tx_envelope.to_xdr(Limits::none()).map_err(|e| {
        ChainError::InvalidData(format!("Failed to encode signed transaction: {}", e))
    })?;

    let signed_xdr_base64 = general_purpose::STANDARD.encode(&signed_xdr_bytes);
    transaction.raw_data = signed_xdr_base64.into_bytes();

    Ok(transaction)
}

#[test]
fn test_encode_for_sign() {
    // Sample unsigned transaction XDR (base64)
    let unsigned_tx_xdr = "AAAAAgAAAABpXkXR6vDcVWLtLrsJ1hp7lWvM+Ye0FtE+mOKbqNqUNgAAAGQAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAGlZcE6Gp11mqHJFzMGxydqvK2dVLuTjGsOFf4DHXS5BAAAAAAAAAAAAA4fkAAAAAAAAAAA=";

    let tx = Transaction {
        raw_data: unsigned_tx_xdr.as_bytes().to_vec(),
        tx_hash: vec![],
        signature: vec![],
        options: None,
    };

    // Test encode_for_sign
    let result = encode_for_sign(tx).unwrap();

    // Should have computed a transaction hash for signing
    assert!(!result.tx_hash.is_empty());
    assert_eq!(result.tx_hash.len(), 32); // Should be 32 bytes

    println!(
        "Transaction hash for signing: {}",
        hex::encode(&result.tx_hash)
    );
}

#[test]
fn test_encode_for_broadcast() {
    // Sample unsigned transaction XDR
    let unsigned_tx_xdr = "AAAAAgAAAABpXkXR6vDcVWLtLrsJ1hp7lWvM+Ye0FtE+mOKbqNqUNgAAAGQAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAGlZcE6Gp11mqHJFzMGxydqvK2dVLuTjGsOFf4DHXS5BAAAAAAAAAAAAA4fkAAAAAAAAAAA=";

    // Sample 64-byte signature (dummy for testing)
    let dummy_signature = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40,
    ];

    let tx = Transaction {
        raw_data: unsigned_tx_xdr.as_bytes().to_vec(),
        tx_hash: vec![],
        signature: dummy_signature,
        options: None,
    };

    // Test encode_for_broadcast
    let result = encode_for_broadcast(tx).unwrap();

    // Should have updated raw_data with signed transaction
    assert!(!result.raw_data.is_empty());

    // The result should be a valid signed transaction XDR
    let signed_xdr = String::from_utf8(result.raw_data).unwrap();
    println!("Signed transaction XDR: {}", signed_xdr);

    // Verify it's a valid XDR by parsing it back
    use base64::{engine::general_purpose, Engine as _};
    let xdr_bytes = general_purpose::STANDARD.decode(&signed_xdr).unwrap();
    let _parsed = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none()).unwrap();
}
