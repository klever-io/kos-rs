use bitcoin::{ecdsa, secp256k1, sighash, Amount, Denomination, Psbt, ScriptBuf};
use kos::chains::{ChainError, ChainOptions, Transaction};

// Helper function to extract BTC options from transaction
fn extract_btc_options(transaction: &Transaction) -> Result<(Vec<Vec<u8>>, Vec<u64>), ChainError> {
    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    match options {
        ChainOptions::BTC {
            prev_scripts,
            input_amounts,
        } => Ok((prev_scripts, input_amounts)),
        _ => Err(ChainError::InvalidOptions),
    }
}

// Helper function to setup PSBT with UTXOs
fn setup_psbt_with_utxos(
    transaction: &Transaction,
    prev_scripts: &[Vec<u8>],
    input_amounts: &[u64],
) -> Result<(Psbt, bitcoin::Transaction, Vec<Amount>), ChainError> {
    let bitcoin_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(transaction.raw_data.as_ref())
            .map_err(|_| ChainError::DecodeRawTx)?;

    let mut psbt =
        Psbt::from_unsigned_tx(bitcoin_transaction.clone()).map_err(|_| ChainError::DecodeRawTx)?;

    let values = input_amounts
        .iter()
        .map(|x| Amount::from_str_in(&x.to_string(), Denomination::Satoshi).unwrap())
        .collect::<Vec<Amount>>();

    for inp_idx in 0..psbt.inputs.len() {
        let utxo = bitcoin::TxOut {
            value: values[inp_idx],
            script_pubkey: prev_scripts[inp_idx].clone().into(),
        };
        psbt.inputs[inp_idx].witness_utxo = Some(utxo);
        psbt.inputs[inp_idx].non_witness_utxo = Some(bitcoin_transaction.clone());
    }

    Ok((psbt, bitcoin_transaction, values))
}

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let (prev_scripts, input_amounts) = extract_btc_options(&transaction)?;
    let (_, bitcoin_transaction, values) =
        setup_psbt_with_utxos(&transaction, &prev_scripts, &input_amounts)?;

    let mut cache = sighash::SighashCache::new(bitcoin_transaction);

    // Compute tx_hash (sighash) for each input
    let mut tx_hash_data = Vec::new();
    for inp_idx in 0..prev_scripts.len() {
        let script_code = prev_scripts[inp_idx].clone();
        let script: ScriptBuf = script_code.into();

        // Determine if it's a legacy or segwit transaction based on script type
        if script.is_p2wpkh() {
            // For SegWit (P2WPKH) transactions
            let sig_hash = cache
                .p2wpkh_signature_hash(
                    inp_idx,
                    &script,
                    values[inp_idx],
                    sighash::EcdsaSighashType::All,
                )
                .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;
            tx_hash_data.extend_from_slice(&sig_hash[..]);
        } else if script.is_p2pkh() {
            // For legacy (P2PKH) transactions
            let sig_hash = cache
                .legacy_signature_hash(inp_idx, &script, sighash::EcdsaSighashType::All.to_u32())
                .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;
            tx_hash_data.extend_from_slice(&sig_hash[..]);
        } else {
            return Err(ChainError::InvalidTransaction(
                "Unsupported script type. Only P2PKH and P2WPKH are supported.".to_string(),
            ));
        };
    }

    transaction.tx_hash = tx_hash_data;

    Ok(transaction)
}

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    public_key: String,
) -> Result<Transaction, ChainError> {
    let (prev_scripts, input_amounts) = extract_btc_options(&transaction)?;
    let (mut psbt, _bitcoin_transaction, _) =
        setup_psbt_with_utxos(&transaction, &prev_scripts, &input_amounts)?;

    let pub_key_bytes = hex::decode(public_key).map_err(|_| ChainError::InvalidPublicKey)?;
    let bit_public_key = bitcoin::PublicKey::from_slice(pub_key_bytes.as_slice())
        .map_err(|_| ChainError::InvalidPublicKey)?;

    // Process signature bytes from transaction.signature
    let signatures = process_signatures(&transaction.signature)?;

    // Add signatures to PSBT and finalize
    for (inp_idx, signature) in signatures.iter().enumerate().take(psbt.inputs.len()) {
        // Create signature object from raw sig bytes
        let sig_hash_ty = sighash::EcdsaSighashType::All;
        let signature = ecdsa::Signature {
            signature: secp256k1::ecdsa::Signature::from_compact(signature)
                .map_err(|_| ChainError::InvalidSignature)?,
            sighash_type: sig_hash_ty,
        };

        // Insert signature
        psbt.inputs[inp_idx]
            .partial_sigs
            .insert(bit_public_key, signature);
    }

    // Finalize PSBT
    for (inp_idx, _) in prev_scripts.iter().enumerate().take(psbt.inputs.len()) {
        let script_pubkey_bytes = prev_scripts[inp_idx].clone();
        let script_pubkey = bitcoin::Script::from_bytes(script_pubkey_bytes.as_slice());

        // Check if it is a legacy or segwit transaction
        let is_legacy = script_pubkey.is_p2pkh();
        let is_segwit = script_pubkey.is_p2wpkh();

        if let Some((pubkey, sig)) = psbt.inputs[inp_idx].partial_sigs.first_key_value() {
            if is_legacy {
                let script_sig_builder = bitcoin::Script::builder()
                    .push_slice(sig.serialize())
                    .push_slice(pubkey.inner.serialize());

                let script = script_sig_builder.as_script();

                psbt.inputs[inp_idx].final_script_sig = Some(ScriptBuf::from(script));
            } else if is_segwit {
                let mut script_witness = bitcoin::Witness::new();
                script_witness.push(sig.to_vec());
                script_witness.push(pubkey.to_bytes());

                psbt.inputs[inp_idx].final_script_witness = Some(script_witness);
            } else {
                // Unsupported script type
                return Err(ChainError::UnsupportedScriptType);
            }
        }
    }

    // TODO: extract_tx is throwing an issue of high fee, so we are bypassing it for now
    // let signed_tx = psbt
    //     .extract_tx()
    //     .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;

    let mut signed_tx = psbt.unsigned_tx.clone();
    for (i, input) in signed_tx.input.iter_mut().enumerate() {
        if let Some(script_sig) = &psbt.inputs[i].final_script_sig {
            input.script_sig = script_sig.clone();
        }
        if let Some(witness) = &psbt.inputs[i].final_script_witness {
            input.witness = witness.clone();
        }
    }

    transaction.raw_data = bitcoin::consensus::encode::serialize(&signed_tx);

    let has_witness = signed_tx.input.iter().any(|x| !x.witness.is_empty());
    if has_witness {
        transaction.signature = bitcoin::consensus::encode::serialize(&signed_tx.compute_wtxid());
    } else {
        transaction.signature = bitcoin::consensus::encode::serialize(&signed_tx.compute_txid());
    }

    transaction.tx_hash = bitcoin::consensus::encode::serialize(&signed_tx.compute_txid());

    Ok(transaction)
}

// Helper function to process signature bytes from transaction.signaturez'
fn process_signatures(signature_data: &[u8]) -> Result<Vec<Vec<u8>>, ChainError> {
    // Each sighash is 32 bytes, so we should have a multiple of 32
    if signature_data.len() % 64 != 0 {
        return Err(ChainError::InvalidSignatureLength);
    }

    let mut signatures = Vec::new();
    for chunk in signature_data.chunks(64) {
        signatures.push(chunk.to_vec());
    }

    Ok(signatures)
}

#[cfg(test)]
mod test {
    use super::*;
    use kos::chains::btc::BTC;
    use kos::chains::Chain;
    use kos::test_utils::get_test_mnemonic;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode("0100000002badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a00000000").unwrap();

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature: vec![],
            options: Some(ChainOptions::BTC {
                prev_scripts: vec![
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                ],
                input_amounts: vec![5000, 10000],
            }),
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(hex::encode(result.tx_hash), "685a9ec4cdaea214dfb48e75930c13aba9ed8980eb6bc93715ae16473deb49cf027756a5570d8871ea32a0367368833f90069803ac3344d40c8d8e7db3451e4b")
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode("0100000002badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a00000000").unwrap();

        let mnemonic = get_test_mnemonic().to_string();
        let btc = BTC::new();
        let seed = btc.mnemonic_to_seed(mnemonic, "".to_string()).unwrap();
        let path = btc.get_path(0, false);
        let pvk = btc.derive(seed, path).unwrap();
        let pbk = btc.get_pbk(pvk.clone()).unwrap();
        let public_key_hex = hex::encode(pbk);

        let signature = vec![
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd3, 0x8f, 0x71, 0x94, 0x7b, 0x2c, 0xf5, 0x43, 0x58,
            0x94, 0x50, 0xdd, 0x80, 0xe3, 0x1d, 0x14, 0x01, 0x2a, 0x45, 0x77, 0x6b, 0x59, 0x90,
            0xa5, 0x49, 0xad, 0x54, 0x07, 0x75, 0x3e, 0x83, 0x02, 0x20, 0x57, 0x62, 0x41, 0xed,
            0x58, 0xfb, 0xd3, 0xcb, 0x2f, 0x74, 0x72, 0x60, 0x9b, 0xb6, 0x15, 0x73, 0x2a, 0x9b,
            0x9d, 0xca, 0x5c, 0x19, 0x97, 0x04, 0x88, 0xd9,
        ];

        let tx = Transaction {
            raw_data: raw_tx,
            tx_hash: vec![],
            signature,
            options: Some(ChainOptions::BTC {
                prev_scripts: vec![
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                    hex::decode("0014546d5f8e86641e4d1eec5b9155a540d953245e4a").unwrap(),
                ],
                input_amounts: vec![5000, 10000],
            }),
        };

        let tx = encode_for_broadcast(tx, public_key_hex).unwrap();

        assert_eq!(hex::encode(tx.raw_data), "01000000000102badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a0247304402203045022100d38f71947b2cf543589450dd80e31d14012a45776b5990a549ad54022007753e830220576241ed58fbd3cb2f7472609bb615732a9b9dca5c19970488d901210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c0000000000");
        assert_eq!(
            hex::encode(tx.signature),
            "56decea9bc90063ad093a1bfe581fe4e8b50a60b4616877ea491cb8b9c4cec4e"
        );
    }
}
