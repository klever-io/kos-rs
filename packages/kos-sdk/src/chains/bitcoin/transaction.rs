use super::BTC;

use kos_crypto::keypair::KeyPair;
use kos_proto::options;
use kos_types::{error::Error, hash::Hash, number::BigNumber};

use bitcoin::{
    absolute::LockTime,
    blockdata::transaction::{Transaction, TxIn, TxOut},
    ecdsa,
    psbt::{self, PartiallySignedTransaction},
    sighash, Address, OutPoint, Sequence,
};

use serde::{Deserialize, Serialize};
use std::{
    ops::{Add, Div, Sub},
    str::FromStr,
};

// Structure to hold Transaction data.
#[derive(Serialize, Debug, Clone)]
pub struct BTCTransaction {
    pub sender_address: Address,
    pub tx: PartiallySignedTransaction,
    pub total_inputs: BigNumber,
    pub total_outputs: BigNumber,
    pub total_send: BigNumber,
    pub change_amount: BigNumber,
    pub change_address: Address,
    pub fee: BigNumber,
    pub sats_per_bytes: BigNumber,
}

impl BTCTransaction {
    pub fn txid(&self) -> String {
        let btc_tx = self.tx.clone().extract_tx();
        btc_tx.txid().to_string()
    }

    pub fn txid_hash(&self) -> Result<Hash, Error> {
        Hash::new(&self.txid())
    }

    pub fn btc_serialize_hex(&self) -> String {
        bitcoin::consensus::encode::serialize_hex(&self.tx.clone().extract_tx())
    }

    pub fn get_signature(&self) -> Result<String, Error> {
        let sig = self.tx.clone().extract_tx().wtxid();
        Ok(sig.to_string())
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        for inp_idx in 0..self.tx.inputs.len() {
            // todo!("multi sig and redeem type");
            let script_witness = {
                match self.tx.inputs[inp_idx].partial_sigs.first_key_value() {
                    Some((pubkey, sig)) => {
                        let mut script_witness = bitcoin::Witness::new();
                        script_witness.push(sig.to_vec());
                        script_witness.push(pubkey.to_bytes());
                        script_witness
                    }
                    _ => return Err(Error::TransportError("No signature found".to_string())),
                }
            };
            self.tx.inputs[inp_idx].final_script_witness = Some(script_witness);
        }

        Ok(())
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> Result<(), Error> {
        // get BIP143 hasher
        let mut cache = sighash::SighashCache::new(&self.tx.unsigned_tx);
        let secp = &secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&keypair.secret_key())
            .map_err(|_| Error::InvalidSignature("private key error"))?;
        let pk = BTC::get_pubkey(&keypair.public_key())?;

        // sign inputs
        for inp_idx in 0..self.tx.inputs.len() {
            // compute sighash
            let msg_sighash_ty_res = self.tx.sighash_ecdsa(inp_idx, &mut cache);

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(Error::InvalidTransaction(format!("{:?}", e))),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            // sign
            let sig = ecdsa::Signature {
                sig: secp.sign_ecdsa(&msg, &sk),
                hash_ty: sighash_ty,
            };

            // insert signature
            self.tx.inputs[inp_idx].partial_sigs.insert(pk, sig);
        }

        Ok(())
    }
}

pub fn create_transaction(
    sender_address: Address,
    sender_utxos: Vec<UTXO>,
    receivers: Vec<(Address, BigNumber)>,
    change_address: Address,
    options: &options::BTCOptions,
) -> Result<BTCTransaction, Error> {
    let total_send = receivers
        .iter()
        .fold(BigNumber::from(0), |acc, (_, amount)| {
            acc.add(amount.clone())
        });

    let mut total_inputs = BigNumber::from(0);
    let mut total_outputs = BigNumber::from(0);

    let mut tx_inputs: Vec<TxIn> = Vec::new();
    let sequence = if options.rbf() {
        Sequence::ENABLE_RBF_NO_LOCKTIME
    } else {
        Sequence::MAX
    };

    let spk = sender_address.script_pubkey();
    let mut psbt_input = Vec::new();
    for utxo in sender_utxos {
        // check for RBF flag
        tx_inputs.push(TxIn {
            previous_output: utxo.to_outpoint()?,
            sequence,
            ..Default::default()
        });

        let amount = BigNumber::from_str(&utxo.value)?;
        total_inputs = total_inputs.add(amount.clone());

        // todo!("allow non segwit inputs")
        psbt_input.push(psbt::Input {
            witness_utxo: Some(TxOut {
                script_pubkey: spk.clone(),
                value: amount.to_u64(),
            }),
            non_witness_utxo: None,
            ..Default::default()
        });
    }

    let sats_per_bytes = options.sats_per_bytes();

    let mut tx_outputs: Vec<TxOut> = Vec::new();

    // Output to receiver
    for (receiver, amount) in receivers {
        tx_outputs.push(TxOut {
            script_pubkey: receiver.script_pubkey(),
            value: amount.to_u64(),
        });

        total_outputs = total_outputs.add(amount);
    }

    let change_output = if total_inputs.gt(&total_send) { 1 } else { 0 };

    // estimate fee
    let fee = estimate_fee(
        tx_inputs.len() as u64,
        tx_outputs.len() as u64 + change_output,
        sats_per_bytes,
    );

    let send_plus_estimated_fee = total_send.clone().add(fee.clone());

    // error if not enough funds to cover fee and amount send
    if total_inputs.lt(&send_plus_estimated_fee) {
        return Err(Error::TransportError(
            format!(
                "Not enough funds to cover fee and amount send. Total inputs: {}, Total send: {}, Fee: {}",
                total_inputs.to_string(),
                total_send.to_string(),
                fee.to_string(),
        )));
    }

    // Output to self (change) if applicable
    // todo add fee calculation
    let change_amount = total_inputs.clone().sub(send_plus_estimated_fee);
    // compute dust value if not provided
    let dust_value = options.dust_value();
    if change_amount.gt(&dust_value) {
        tx_outputs.push(TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: change_amount.clone().to_u64(),
        });

        total_outputs = total_outputs.add(change_amount.clone());
    }

    let fee = total_inputs.clone().sub(total_outputs.clone());
    let size = estimate_size(tx_inputs.len() as u64, tx_outputs.len() as u64);
    let sats_per_bytes = fee.clone().div(BigNumber::from(size));

    // Build Transaction
    let mut tx = PartiallySignedTransaction::from_unsigned_tx(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    })
    .map_err(|e| Error::InvalidTransaction(format!("creating psbt: {}", e)))?;

    // update inputs
    tx.inputs = psbt_input;

    Ok(BTCTransaction {
        sender_address,
        tx,
        total_inputs,
        total_outputs,
        total_send,
        fee,
        change_amount,
        change_address,
        sats_per_bytes,
    })
}

// Structure to hold UTXO data.
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub value: String,
    #[serde(default)]
    pub height: u64,
    pub confirmations: u64,
}

impl UTXO {
    pub fn to_outpoint(&self) -> Result<OutPoint, Error> {
        let txid = bitcoin::Txid::from_str(&self.txid)
            .map_err(|e| Error::InvalidTransaction(e.to_string()))?;
        let outpoint = OutPoint::new(txid, self.vout);
        Ok(outpoint)
    }

    pub fn amount(&self) -> BigNumber {
        BigNumber::from_string(&self.value).unwrap_or_default()
    }
}

pub fn estimate_size(tx_in: u64, tx_out: u64) -> u64 {
    (148 * tx_in) + (34 * tx_out + 10)
}

// EstimateFee based on Transaction size
pub fn estimate_fee(tx_in: u64, tx_out: u64, sats_per_bytes: u64) -> BigNumber {
    BigNumber::from(estimate_size(tx_in, tx_out) * sats_per_bytes)
}
