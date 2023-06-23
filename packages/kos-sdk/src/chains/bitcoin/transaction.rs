use kos_types::{error::Error, number::BigNumber};

use bitcoin::{
    absolute::LockTime,
    blockdata::transaction::{TxIn, TxOut},
    Address, OutPoint,
};

use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub type BTCTransaction = bitcoin::blockdata::transaction::Transaction;

pub fn create_transaction(
    sender_utxos: Vec<UTXO>,
    receivers: Vec<(Address, BigNumber)>,
    sats_per_bytes: u64,
    change_address: Address,
    dust_value: Option<BigNumber>,
) -> Result<BTCTransaction, Error> {
    let total_send = receivers
        .iter()
        .fold(BigNumber::from(0), |acc, (_, amount)| acc.add(amount));

    let mut total_amount = BigNumber::from(0);

    let mut tx_inputs: Vec<TxIn> = Vec::new();
    for utxo in sender_utxos {
        tx_inputs.push(TxIn {
            previous_output: utxo.to_outpoint()?,
            ..Default::default()
        });

        total_amount = total_amount.add(&BigNumber::from_str(&utxo.value)?);
    }

    let mut tx_outputs: Vec<TxOut> = Vec::new();

    // Output to receiver
    for (receiver, amount) in receivers {
        tx_outputs.push(TxOut {
            script_pubkey: receiver.script_pubkey(),
            value: amount.to_u64(),
        });
    }

    // estimate fee
    let fee = estimate_fee(
        tx_inputs.len() as u64,
        tx_outputs.len() as u64,
        sats_per_bytes,
    );

    // Output to self (change) if applicable
    // todo add fee calculation
    let change_amount = total_amount.sub(&total_send.add(&fee));
    // compute dust value if not provided
    let dust_value = dust_value.unwrap_or(BigNumber::from(148 * sats_per_bytes));
    if change_amount.gt(&dust_value) {
        tx_outputs.push(TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: change_amount.to_u64(),
        });
    }

    // Build Transaction
    let tx = bitcoin::blockdata::transaction::Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    Ok(tx)
}

// Structure to hold UTXO data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub value: String,
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
