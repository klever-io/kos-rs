use kos::chains::{ChainError, Transaction};
use sha2::{Digest, Sha256};

/// NEAR Protocol codec — encode/decode for transaction signing and broadcast.
///
/// ## Protocol summary
/// - Transactions are **Borsh**-serialised raw bytes (`raw_data`).
/// - The hash to sign is `SHA-256(raw_data)` (32 bytes).
/// - A `SignedTransaction` on the wire is:
///   `raw_data || signature_enum`
///   where `signature_enum` = `0x00` (Ed25519 variant tag) || 64-byte Ed25519 signature.
///
/// References:
/// - <https://nomicon.io/RuntimeSpec/Transactions>
/// - <https://borsh.io/>
///
// ------------------------------------------------------------------
// encode_for_sign
// ------------------------------------------------------------------
/// Compute the signing hash for a NEAR transaction.
///
/// Expects `transaction.raw_data` to contain the Borsh-serialised
/// `Transaction` object (unsigned).  Fills `transaction.tx_hash` with
/// the 32-byte SHA-256 digest, which is what the Ed25519 key signs.
pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    if transaction.raw_data.is_empty() {
        return Err(ChainError::InvalidData(
            "NEAR: raw_data must not be empty".to_string(),
        ));
    }

    let hash = Sha256::digest(&transaction.raw_data);
    transaction.tx_hash = hash.to_vec();

    Ok(transaction)
}

// ------------------------------------------------------------------
// encode_for_broadcast
// ------------------------------------------------------------------

/// Assemble a NEAR `SignedTransaction` ready for broadcast.
///
/// The wire format is the Borsh-encoded `SignedTransaction`:
/// ```text
/// <Transaction bytes (raw_data)>
/// <Signature enum>
///   byte[0]    = 0x00   (KeyType::ED25519)
///   byte[1..65]= 64-byte Ed25519 signature
/// ```
///
/// On success the signed bytes are placed back in `transaction.raw_data`.
pub fn encode_for_broadcast(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    if transaction.raw_data.is_empty() {
        return Err(ChainError::InvalidData(
            "NEAR: raw_data must not be empty".to_string(),
        ));
    }

    if transaction.signature.len() != 64 {
        return Err(ChainError::InvalidSignatureLength);
    }

    // Build SignedTransaction = Transaction bytes + Signature enum (1 tag + 64 bytes)
    let mut signed = Vec::with_capacity(transaction.raw_data.len() + 65);
    signed.extend_from_slice(&transaction.raw_data);
    signed.push(0x00); // Ed25519 variant tag
    signed.extend_from_slice(&transaction.signature);

    transaction.raw_data = signed;
    Ok(transaction)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

    /// Minimal valid Borsh-encoded NEAR Transaction payload for testing.
    /// (Arbitrarily chosen bytes — tests only validate codec behaviour, not
    /// real on-chain semantics.)
    fn sample_raw_tx() -> Vec<u8> {
        // 40 bytes: enough to simulate a non-trivial payload
        (0u8..40).collect()
    }

    fn sample_signature() -> Vec<u8> {
        (0u8..64).collect()
    }

    // ------------------------------------------------------------------

    #[test]
    fn test_encode_for_sign_sets_hash() {
        let raw = sample_raw_tx();
        let expected_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&raw).to_vec()
        };

        let tx = Transaction {
            raw_data: raw,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(result.tx_hash.len(), 32, "hash must be 32 bytes (SHA-256)");
        assert_eq!(
            result.tx_hash, expected_hash,
            "hash must equal SHA-256(raw_data)"
        );
    }

    #[test]
    fn test_encode_for_sign_empty_raw_data_fails() {
        let tx = Transaction {
            raw_data: vec![],
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        assert!(encode_for_sign(tx).is_err());
    }

    #[test]
    fn test_encode_for_sign_is_deterministic() {
        let raw = sample_raw_tx();

        let tx1 = Transaction {
            raw_data: raw.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };
        let tx2 = Transaction {
            raw_data: raw,
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };

        let r1 = encode_for_sign(tx1).unwrap();
        let r2 = encode_for_sign(tx2).unwrap();
        assert_eq!(r1.tx_hash, r2.tx_hash);
    }

    // ------------------------------------------------------------------

    #[test]
    fn test_encode_for_broadcast_layout() {
        let raw = sample_raw_tx();
        let sig = sample_signature();

        let tx = Transaction {
            raw_data: raw.clone(),
            tx_hash: vec![],
            signature: sig.clone(),
            options: None,
        };

        let result = encode_for_broadcast(tx).unwrap();

        // signed = raw_data || 0x00 (tag) || signature (64 bytes)
        let expected_len = raw.len() + 1 + 64;
        assert_eq!(result.raw_data.len(), expected_len);

        // Verify prefix equals original raw_data
        assert_eq!(&result.raw_data[..raw.len()], raw.as_slice());

        // Verify Ed25519 variant tag
        assert_eq!(result.raw_data[raw.len()], 0x00, "Ed25519 tag must be 0x00");

        // Verify signature bytes
        assert_eq!(&result.raw_data[raw.len() + 1..], sig.as_slice());
    }

    #[test]
    fn test_encode_for_broadcast_wrong_signature_length_fails() {
        let tx_short = Transaction {
            raw_data: sample_raw_tx(),
            tx_hash: vec![],
            signature: vec![0u8; 63], // one byte short
            options: None,
        };
        assert!(encode_for_broadcast(tx_short).is_err());

        let tx_long = Transaction {
            raw_data: sample_raw_tx(),
            tx_hash: vec![],
            signature: vec![0u8; 65], // one byte too many
            options: None,
        };
        assert!(encode_for_broadcast(tx_long).is_err());
    }

    #[test]
    fn test_encode_for_broadcast_empty_raw_data_fails() {
        let tx = Transaction {
            raw_data: vec![],
            tx_hash: vec![],
            signature: sample_signature(),
            options: None,
        };
        assert!(encode_for_broadcast(tx).is_err());
    }

    #[test]
    fn test_full_round_trip() {
        // 1. sign phase
        let raw = sample_raw_tx();
        let tx = Transaction {
            raw_data: raw.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: None,
        };
        let signed_tx = encode_for_sign(tx).unwrap();
        assert_eq!(signed_tx.tx_hash.len(), 32);

        // 2. broadcast phase (simulate: attach signature)
        let tx_with_sig = Transaction {
            raw_data: raw.clone(),
            tx_hash: signed_tx.tx_hash.clone(),
            signature: sample_signature(),
            options: None,
        };
        let broadcast_tx = encode_for_broadcast(tx_with_sig).unwrap();

        assert_eq!(broadcast_tx.raw_data.len(), raw.len() + 65);
        assert_eq!(&broadcast_tx.raw_data[..raw.len()], raw.as_slice());
        assert_eq!(broadcast_tx.raw_data[raw.len()], 0x00);
    }
}
