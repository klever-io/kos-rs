use base64::{engine::general_purpose, Engine as _};
use kos::{
    chains::{ChainError, Transaction},
    crypto::base64::simple_base64_decode,
};
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    BytesM, DecoratedSignature, EnvelopeType, Hash, Limits, ReadXdr, Signature, SignatureHint,
    TransactionEnvelope, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    WriteXdr,
};

// Network passphrases
const MAINNET_PASSPHRASE: &[u8] = b"Public Global Stellar Network ; September 2015";
const _TESTNET_PASSPHRASE: &[u8] = b"Test SDF Network ; September 2015";

// Function to calculate network ID from passphrase
fn calculate_network_id(passphrase: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase);
    hasher.finalize().into()
}

pub fn encode_for_sign(transaction: Transaction) -> Result<Transaction, ChainError> {
    encode_for_sign_with_passphrase(transaction, MAINNET_PASSPHRASE)
}

pub fn encode_for_sign_with_passphrase(
    mut transaction: Transaction,
    passphrase: &[u8],
) -> Result<Transaction, ChainError> {
    // Calculate network ID from passphrase
    let network_id = calculate_network_id(passphrase);

    // Decode the base64 first, then parse XDR
    let xdr_bytes = transaction.raw_data.clone();

    let tx_envelope = TransactionEnvelope::from_xdr(&xdr_bytes, Limits::none())
        .map_err(|e| ChainError::InvalidData(format!("Failed to parse XDR: {}", e)))?;

    // Compute the signature base following Stellar's protocol
    let signature_base = match &tx_envelope {
        TransactionEnvelope::TxV0(v0_env) => {
            // Para V0, usar ENVELOPE_TYPE_TX para backwards compatibility
            let envelope_type = EnvelopeType::Tx;
            let envelope_type_bytes = envelope_type.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode envelope type: {}", e))
            })?;

            let tx_xdr = v0_env.tx.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;

            // Signature base = network_id + envelope_type_bytes + tx_xdr
            let mut signature_base = Vec::new();
            signature_base.extend_from_slice(&network_id);
            signature_base.extend_from_slice(&envelope_type_bytes);
            signature_base.extend_from_slice(&tx_xdr);
            signature_base
        }
        TransactionEnvelope::Tx(v1_env) => {
            let tx_signature_payload_tagged_transaction =
                TransactionSignaturePayloadTaggedTransaction::Tx(v1_env.tx.clone());

            let payload = TransactionSignaturePayload {
                network_id: Hash::from(network_id),
                tagged_transaction: tx_signature_payload_tagged_transaction,
            };

            let tx_xdr = payload.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;

            tx_xdr
        }
        TransactionEnvelope::TxFeeBump(fee_bump_env) => {
            let envelope_type = EnvelopeType::TxFeeBump;
            let envelope_type_bytes = envelope_type.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode envelope type: {}", e))
            })?;

            let tx_xdr = fee_bump_env.tx.to_xdr(Limits::none()).map_err(|e| {
                ChainError::InvalidData(format!("Failed to encode transaction: {}", e))
            })?;

            let mut signature_base = Vec::new();
            signature_base.extend_from_slice(&network_id);
            signature_base.extend_from_slice(&envelope_type_bytes);
            signature_base.extend_from_slice(&tx_xdr);
            signature_base
        }
    };

    // Hash the signature base to get the transaction hash
    let tx_hash = Sha256::digest(&signature_base);
    transaction.tx_hash = tx_hash.to_vec();

    Ok(transaction)
}

pub fn encode_for_broadcast(
    transaction: Transaction,
    public_key_hex: String,
) -> Result<Transaction, ChainError> {
    // Convert hex public key to bytes
    let public_key_bytes = hex::decode(&public_key_hex)
        .map_err(|_| ChainError::InvalidData("Invalid public key hex".to_string()))?;

    if public_key_bytes.len() != 32 {
        return Err(ChainError::InvalidData(
            "Public key must be 32 bytes".to_string(),
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    encode_for_broadcast_with_pubkey(transaction, &public_key)
}

pub fn encode_for_broadcast_with_pubkey(
    mut transaction: Transaction,
    public_key: &[u8; 32],
) -> Result<Transaction, ChainError> {
    // Parse the original transaction from raw_data
    let xdr_bytes = transaction.raw_data.clone();

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
    // Create signature hint from last 4 bytes of public key (like Go SDK)
    let mut hint_bytes = [0u8; 4];
    hint_bytes.copy_from_slice(&public_key[28..32]);

    let decorated_signature = DecoratedSignature {
        hint: SignatureHint(hint_bytes),
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
    let unsigned_tx_xdr = simple_base64_decode("AAAAAgAAAACn54ed9JVAQdXN6d0E5Q+QH/0BOFi5/jWw3LII81gdPgAAAGQDcl2eAAAAGQAAAAEAAAAAAAAAAAAAAABobmAtAAAAAAAAAAEAAAAAAAAAAQAAAAAvdBR3bp6jt7IkpRzKY3SZsapC3gFKYPBm3sN2Ss3C7QAAAAAAAAAAAAAAAQAAAAAAAAAA").unwrap();

    let tx = Transaction {
        raw_data: unsigned_tx_xdr,
        tx_hash: vec![],
        signature: vec![],
        options: None,
    };

    // Test encode_for_sign
    let result = encode_for_sign(tx).unwrap();

    // Should have computed a transaction hash for signing
    assert!(!result.tx_hash.is_empty());
    assert_eq!(result.tx_hash.len(), 32); // Should be 32 bytes
}

#[test]
fn test_encode_for_broadcast() {
    // Sample unsigned transaction XDR
    let unsigned_tx_xdr = simple_base64_decode("AAAAAgAAAABpXkXR6vDcVWLtLrsJ1hp7lWvM+Ye0FtE+mOKbqNqUNgAAAGQAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAGlZcE6Gp11mqHJFzMGxydqvK2dVLuTjGsOFf4DHXS5BAAAAAAAAAAAAA4fkAAAAAAAAAAA=").unwrap();

    // Sample 64-byte signature (dummy for testing)
    let dummy_signature = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40,
    ];

    let tx = Transaction {
        raw_data: unsigned_tx_xdr,
        tx_hash: vec![],
        signature: dummy_signature,
        options: None,
    };

    // Test encode_for_broadcast with dummy public key
    let dummy_public_key_hex =
        "a79787f3a5511a41d5cde9dd04e50f901ffd010858b9fe35b0dcb208f3581d3e".to_string();
    let result = encode_for_broadcast(tx, dummy_public_key_hex).unwrap();

    // Should have updated raw_data with signed transaction
    assert!(!result.raw_data.is_empty());
}
