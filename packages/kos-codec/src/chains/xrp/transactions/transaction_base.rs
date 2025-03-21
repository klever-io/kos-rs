use kos::chains::ChainError;

use xrpl::core::binarycodec::{
    definitions::{load_definition_map, DefinitionHandler, FieldInstance},
    types::{account_id::AccountId, amount::Amount, blob::Blob, Hash256, STArray, XRPLType},
};

#[derive(Debug)]
pub struct TransactionCommon {
    pub transaction_type: u16,
    pub account: AccountId,
    pub fee: Option<Amount>,
    pub sequence: Option<u32>,
    pub account_txn_id: Option<Hash256>,
    pub last_ledger_sequence: Option<u32>,
    pub memos: Option<STArray>,
    pub network_id: Option<u32>,
    pub source_tag: Option<u32>,
    pub signing_pub_key: Option<Blob>,
    pub ticket_sequence: Option<u32>,
    pub txn_signature: Option<Blob>,
}

impl TransactionCommon {
    pub fn from(buffer: Vec<(FieldInstance, Vec<u8>)>) -> Result<Self, ChainError> {
        let mut transaction_type: u16 = 0;
        let mut account: AccountId = AccountId::new(None).map_err(|_| ChainError::DecodeRawTx)?;
        let mut fee: Option<Amount> = None;
        let mut sequence: Option<u32> = None;
        let mut account_txn_id: Option<Hash256> = None;
        let mut last_ledger_sequence: Option<u32> = None;
        let mut memos: Option<STArray> = None;
        let mut network_id: Option<u32> = None;
        let mut source_tag: Option<u32> = None;
        let mut signing_pub_key: Option<Blob> = None;
        let mut ticket_sequence: Option<u32> = None;
        let mut txn_signature: Option<Blob> = None;

        for value in buffer {
            match value.0.name.as_str() {
                "TransactionType" => {
                    transaction_type = u16::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    );
                }
                "Account" => {
                    account = AccountId::new(Some(value.1.as_ref()))
                        .map_err(|_| ChainError::DecodeRawTx)?;
                }
                "Fee" => {
                    fee = Some(
                        Amount::new(Some(value.1.as_ref())).map_err(|_| ChainError::DecodeRawTx)?,
                    );
                }
                "Sequence" => {
                    sequence = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "AccountTxnID" => {
                    account_txn_id = Some(
                        Hash256::new(Some(value.1.as_ref()))
                            .map_err(|_| ChainError::DecodeRawTx)?,
                    );
                }
                "LastLedgerSequence" => {
                    last_ledger_sequence = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "Memos" => {
                    memos = Some(
                        STArray::new(Some(value.1.as_ref()))
                            .map_err(|_| ChainError::DecodeRawTx)?,
                    );
                }
                "NetworkID" => {
                    network_id = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "SourceTag" => {
                    source_tag = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "SigningPubKey" => {
                    signing_pub_key =
                        Some(Blob::new(Some(&value.1)).map_err(|_| ChainError::DecodeRawTx)?);
                }
                "TicketSequence" => {
                    ticket_sequence = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "TxnSignature" => {
                    txn_signature =
                        Some(Blob::new(Some(&value.1)).map_err(|_| ChainError::DecodeRawTx)?);
                }
                _ => {}
            }
        }

        Ok(TransactionCommon {
            transaction_type,
            account,
            account_txn_id,
            fee,
            last_ledger_sequence,
            memos,
            network_id,
            sequence,
            signing_pub_key,
            txn_signature,
            source_tag,
            ticket_sequence,
        })
    }

    pub fn serialize(&self) -> Vec<(FieldInstance, Vec<u8>)> {
        let mut fields_and_value: Vec<(FieldInstance, Vec<u8>)> = Vec::new();

        let definition_map: &xrpl::core::binarycodec::definitions::DefinitionMap =
            load_definition_map();

        if let Some(field_instance) = definition_map.get_field_instance("TransactionType") {
            fields_and_value.extend_from_slice(&[(
                field_instance.clone(),
                self.transaction_type.to_be_bytes().to_vec(),
            )]);
        }

        if let Some(field_instance) = definition_map.get_field_instance("NetworkID") {
            if let Some(network_id) = self.network_id {
                let network_id = network_id.to_be_bytes();
                fields_and_value.extend_from_slice(&[(field_instance, network_id.to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("SourceTag") {
            if let Some(source_tag) = self.source_tag {
                fields_and_value
                    .extend_from_slice(&[(field_instance, source_tag.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Sequence") {
            if let Some(sequence) = self.sequence {
                fields_and_value
                    .extend_from_slice(&[(field_instance, sequence.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("LastLedgerSequence") {
            if let Some(last_ledger_sequence) = self.last_ledger_sequence {
                let last_ledger_sequence = last_ledger_sequence.to_be_bytes();
                fields_and_value
                    .extend_from_slice(&[(field_instance, last_ledger_sequence.to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Memos") {
            if let Some(memos) = &self.memos {
                fields_and_value.extend_from_slice(&[(field_instance, memos.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("TicketSequence") {
            if let Some(ticket_sequence) = self.ticket_sequence {
                fields_and_value
                    .extend_from_slice(&[(field_instance, ticket_sequence.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("AccountTxnID") {
            if let Some(account_txn_id) = self.account_txn_id.clone() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, account_txn_id.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Fee") {
            if let Some(fee) = self.fee.as_ref() {
                fields_and_value.extend_from_slice(&[(field_instance, fee.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("SigningPubKey") {
            if let Some(signing_pub_key) = self.signing_pub_key.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, signing_pub_key.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("TxnSignature") {
            if let Some(signature) = self.txn_signature.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, signature.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Account") {
            fields_and_value.extend_from_slice(&[(field_instance, self.account.as_ref().to_vec())]);
        }

        fields_and_value
    }
}
