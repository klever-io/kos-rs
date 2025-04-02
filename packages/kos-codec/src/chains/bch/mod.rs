mod sig_hash;

use bitcoin::{hashes::Hash, Amount, Denomination, Psbt, ScriptBuf};
use kos::chains::{ChainError, ChainOptions, Transaction};

pub fn encode_for_sign(mut transaction: Transaction) -> Result<Transaction, ChainError> {
    let bitcoin_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(transaction.raw_data.as_ref())
            .map_err(|_| ChainError::DecodeRawTx)?;

    let sighash_type = sig_hash::SIGHASH_ALL | sig_hash::SIGHASH_FORKID;

    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    let (prev_scripts, input_amounts) = match options {
        ChainOptions::BTC {
            prev_scripts,
            input_amounts,
        } => (prev_scripts, input_amounts),
        _ => {
            return Err(ChainError::InvalidOptions);
        }
    };

    let mut sighash_vec = Vec::new();

    for idx in 0..bitcoin_transaction.input.len() {
        let mut cache = sig_hash::SigHashCache::new();
        let script_code = prev_scripts[idx].clone();

        let hash = sig_hash::bip143_sighash(
            &bitcoin_transaction,
            idx,
            &script_code,
            input_amounts[idx] as i64,
            sighash_type,
            &mut cache,
        )
        .map_err(|_| ChainError::DecodeRawTx)?;

        sighash_vec.push(hash.to_byte_array());
    }

    transaction.signature = sighash_vec.iter().flat_map(|sig| sig.to_vec()).collect();

    Ok(transaction)
}

pub fn encode_for_broadcast(
    mut transaction: Transaction,
    public_key: String,
) -> Result<Transaction, ChainError> {
    let options = transaction
        .options
        .clone()
        .ok_or(ChainError::MissingOptions)?;

    let (prev_scripts, input_amounts) = match options {
        ChainOptions::BTC {
            prev_scripts,
            input_amounts,
        } => (prev_scripts, input_amounts),
        _ => {
            return Err(ChainError::InvalidOptions);
        }
    };

    let bitcoin_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(transaction.raw_data.as_ref())
            .map_err(|_| ChainError::DecodeRawTx)?;

    let mut psbt =
        Psbt::from_unsigned_tx(bitcoin_transaction.clone()).map_err(|_| ChainError::DecodeRawTx)?;

    let pub_key_bytes = hex::decode(public_key).map_err(|_| ChainError::InvalidPublicKey)?;
    let bit_public_key = bitcoin::PublicKey::from_slice(pub_key_bytes.as_slice())
        .map_err(|_| ChainError::InvalidPublicKey)?;

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

        // Add non_witness_utxo
        psbt.inputs[inp_idx].non_witness_utxo = Some(bitcoin_transaction.clone());
    }

    let mut cursor = 0;
    let mut signatures: Vec<Vec<u8>> = Vec::new();

    let num_vecs = u32::from_le_bytes(
        transaction.signature[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ChainError::DecodeRawTx)?,
    ) as usize;
    cursor += 4;
    for _ in 0..num_vecs {
        let vec_size = u32::from_le_bytes(
            transaction.signature[cursor..cursor + 4]
                .try_into()
                .map_err(|_| ChainError::DecodeRawTx)?,
        ) as usize;

        cursor += 4;

        if transaction.signature.len() < cursor + vec_size {
            return Err(ChainError::DecodeRawTx); //Err("Dados serializados muito curtos (faltando dados do vetor interno).");
        }

        let fixed_size_vec = transaction.signature[cursor..cursor + vec_size].to_vec();
        cursor += vec_size;
        signatures.push(fixed_size_vec);
    }

    if signatures.len()
        != prev_scripts
            .iter()
            .enumerate()
            .take(psbt.inputs.len())
            .len()
    {
        return Err(ChainError::DecodeRawTx); //Err("signatures lenght does not match prev_script lenght");
    }

    // finalize
    for (inp_idx, _) in prev_scripts.iter().enumerate().take(psbt.inputs.len()) {
        let a = signatures[inp_idx].as_slice();
        let mut b = bitcoin::script::PushBytesBuf::new();
        let _ = b.extend_from_slice(a);

        let script_sig_builder = bitcoin::Script::builder()
            .push_slice(b)
            .push_slice(bit_public_key.inner.serialize());

        let script = script_sig_builder.as_script();

        psbt.inputs[inp_idx].final_script_sig = Some(ScriptBuf::from(script));
    }

    let signed_tx = psbt
        .extract_tx()
        .map_err(|e| ChainError::InvalidTransaction(e.to_string()))?;

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

#[cfg(test)]
mod test {
    use crate::KosCodedAccount;

    use super::*;

    #[test]
    fn test_encode_for_sign() {
        let raw_tx = hex::decode("0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000").unwrap();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature: vec![],
            options: Some(kos::chains::ChainOptions::BTC {
                prev_scripts: vec![
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                ],
                input_amounts: vec![498870, 1001016],
            }),
        };

        let result = encode_for_sign(tx).unwrap();

        assert_eq!(hex::encode(result.signature), "3bb9d471a2ddecc4e1d77cd7ae442e4f024e80615f7b616c04045362092fe8316b7f20194c402047f01803f8a2c125bb7fab49c764c5d436b1b3443d5c118be4");
    }

    #[test]
    fn test_encode_for_broadcast() {
        let raw_tx = hex::decode("0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000").unwrap();

        let signature = hex::decode("0200000048000000304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a414700000030440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d41").unwrap();

        let tx = Transaction {
            raw_data: raw_tx.clone(),
            tx_hash: vec![],
            signature,
            options: Some(kos::chains::ChainOptions::BTC {
                prev_scripts: vec![
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                    hex::decode("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac").unwrap(),
                ],
                input_amounts: vec![498870, 1001016],
            }),
        };

        let account = KosCodedAccount {
            chain_id: 18,
            address: "qpdmpwjm5kxd4dze7flj6205pcwatkersyxhanv8c4".to_string(),
            public_key: "02bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217"
                .to_string(),
        };

        let result = encode_for_broadcast(tx.clone(), account.public_key.to_string()).unwrap();

        assert_eq!(hex::encode(result.raw_data), "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d010000006b48304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c010000006a4730440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000");
    }
}
