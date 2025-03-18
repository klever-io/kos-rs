use crate::chains::xrp::constants;
use crate::chains::xrp::models::deserialize_object;
use crate::chains::xrp::transactions::{
    transaction_base::TransactionCommon, Serialize, Transaction,
};
use crate::chains::ChainError;

use std::collections::HashMap;
use xrpl::{
    core::{
        binarycodec::{
            definitions::{load_definition_map, DefinitionHandler, FieldInstance},
            types::{
                account_id::AccountId, blob::Blob, xchain_bridge::XChainBridge, Amount, Currency,
                Hash128, Hash160, Hash256, STArray, XRPLType,
            },
            Serialization,
        },
        BinarySerializer, Parser,
    },
    utils::ToBytes,
};

#[derive(Debug)]
pub struct PaymentTransaction {
    pub fields_and_values: HashMap<String, FieldInstance>,
    pub common: TransactionCommon,
    pub flags: Option<u32>,
    pub amount: Amount,
    pub destination: AccountId,
    pub destination_tag: Option<u32>,
    pub invoice_id: Option<Hash256>,
    pub send_max: Option<Amount>,
    pub deliver_min: Option<Amount>,
}

impl Transaction for PaymentTransaction {
    // fn common(&self) -> &TransactionCommon {
    //     &self.common
    // }

    fn common_mut(&mut self) -> &mut TransactionCommon {
        &mut self.common
    }
}

impl Serialize for PaymentTransaction {
    fn serialize(&self) -> Result<Vec<u8>, ChainError> {
        let mut serializer = BinarySerializer::new();

        let definition_map = load_definition_map();

        if let Some(field_instance) = definition_map.get_field_instance("TransactionType") {
            serializer.write_field_and_value(
                field_instance.clone(),
                definition_map
                    .get_transaction_type_code("Payment")
                    .unwrap()
                    .to_be_bytes()
                    .as_ref(),
                false,
            );
        }

        if let Some(field_instance) = definition_map.get_field_instance("NetworkID") {
            if let Some(network_id) = self.common.network_id {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    network_id.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("SourceTag") {
            if let Some(source_tag) = self.common.source_tag {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    source_tag.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Flags") {
            if let Some(flags) = self.flags {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    flags.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("Sequence") {
            if let Some(sequence) = self.common.sequence {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    sequence.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("LastLedgerSequence") {
            if let Some(last_ledger_sequence) = self.common.last_ledger_sequence {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    last_ledger_sequence.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("Memos") {
            if let Some(memos) = &self.common.memos {
                serializer.write_field_and_value(field_instance.clone(), memos.as_ref(), false);
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("TicketSequence") {
            if let Some(ticket_sequence) = self.common.ticket_sequence {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    ticket_sequence.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("AccountTxnID") {
            if let Some(account_txn_id) = self.common.account_txn_id.clone() {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    account_txn_id.as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("DestinationTag") {
            if let Some(destination_tag) = self.destination_tag {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    destination_tag.to_be_bytes().as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("Amount") {
            serializer.write_field_and_value(field_instance.clone(), self.amount.as_ref(), false);
        }

        if let Some(field_instance) = self.fields_and_values.get("Fee") {
            if let Some(fee) = self.common.fee.as_ref() {
                serializer.write_field_and_value(field_instance.clone(), fee.as_ref(), false);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("SigningPubKey") {
            if let Some(signing_pub_key) = self.common.signing_pub_key.as_ref() {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    signing_pub_key.as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("TxnSignature") {
            if let Some(signature) = self.common.txn_signature.as_ref() {
                serializer.write_field_and_value(field_instance.clone(), signature.as_ref(), false);
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("Account") {
            serializer.write_field_and_value(
                field_instance.clone(),
                self.common.account.as_ref(),
                false,
            );
        }

        if let Some(field_instance) = self.fields_and_values.get("Destination") {
            serializer.write_field_and_value(
                field_instance.clone(),
                self.destination.as_ref(),
                false,
            );
        }

        if let Some(field_instance) = self.fields_and_values.get("InvoiceID") {
            if let Some(invoice_id) = self.invoice_id.clone() {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    invoice_id.as_ref(),
                    false,
                );
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("SendMax") {
            if let Some(send_max) = self.send_max.clone() {
                serializer.write_field_and_value(field_instance.clone(), send_max.as_ref(), false);
            }
        }

        if let Some(field_instance) = self.fields_and_values.get("DeliverMin") {
            if let Some(deliver_min) = self.deliver_min.clone() {
                serializer.write_field_and_value(
                    field_instance.clone(),
                    deliver_min.as_ref(),
                    false,
                );
            }
        }

        Ok(serializer)
    }
}

// decode payment transaction
pub fn decode_payment_transaction(buffer: &[u8]) -> Result<PaymentTransaction, ChainError> {
    let mut fields_and_values: HashMap<String, FieldInstance> = HashMap::new();
    let mut account: AccountId = AccountId::new(None).unwrap();
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

    let mut flags: Option<u32> = Some(0);
    let mut amount: Amount = Amount::new(None).unwrap();
    let mut destination: AccountId = AccountId::new(None).unwrap();
    let mut destination_tag: Option<u32> = None;
    let mut invoice_id: Option<Hash256> = None;
    let mut send_max: Option<Amount> = None;
    let mut deliver_min: Option<Amount> = None;

    let mut binary_parser = xrpl::core::BinaryParser::from(buffer);
    while !binary_parser.is_end(None) {
        let field_info = binary_parser.read_field().unwrap();

        match field_info.clone().associated_type.as_str() {
            "AccountID" => {
                let field_value: AccountId =
                    binary_parser.read_field_value(&field_info.clone()).unwrap();

                if field_info.name == "Account" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    account = field_value.clone();
                }

                if field_info.name == "Destination" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    destination = field_value;
                }
            }
            "Amount" => {
                let field_value: Amount = binary_parser.read_field_value(&field_info).unwrap();

                if field_info.name == "Fee" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    fee = Some(field_value.clone());
                }

                if field_info.name == "Amount" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    amount = field_value.clone()
                }

                if field_info.name == "DeliverMax" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    send_max = Some(field_value.clone())
                }

                if field_info.name == "DeliverMin" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    deliver_min = Some(field_value)
                }
            }
            "Blob" => {
                let length_prefix = binary_parser.read_length_prefix().unwrap();
                let content = binary_parser.read(length_prefix).unwrap();

                let field_value: Blob = Blob::new(Some(&content)).unwrap();

                if field_info.name == "SigningPubKey" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    signing_pub_key = Some(field_value.clone())
                }

                if field_info.name == "TxnSignature" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    txn_signature = Some(field_value)
                }
            }
            "Currency" => {
                let _: Currency = binary_parser.read_field_value(&field_info).unwrap();
            }
            "Hash128" => {
                let _: Hash128 = binary_parser.read_field_value(&field_info).unwrap();
            }
            "Hash160" => {
                let _: Hash160 = binary_parser.read_field_value(&field_info).unwrap();
            }
            "Hash256" => {
                let field_value: Hash256 = binary_parser.read_field_value(&field_info).unwrap();

                if field_info.name == "InvoiceID" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    invoice_id = Some(field_value.clone())
                }

                if field_info.name == "AccountTxnID" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    account_txn_id = Some(field_value)
                }
            }
            "XChainClaimID" => {
                let _: XChainBridge = binary_parser.read_field_value(&field_info).unwrap();
            }
            "UInt8" => {
                let _: u8 = binary_parser.read_uint8().unwrap();
            }
            "UInt16" => {
                let _: u16 = binary_parser.read_uint16().unwrap();
            }
            "UInt32" => {
                let field_value: u32 = binary_parser.read_uint32().unwrap();

                if field_info.name == "Sequence" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    sequence = Some(field_value)
                }

                if field_info.name == "LastLedgerSequence" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    last_ledger_sequence = Some(field_value)
                }

                if field_info.name == "NetworkID" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    network_id = Some(field_value)
                }

                if field_info.name == "SourceTag" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    source_tag = Some(field_value)
                }

                if field_info.name == "TicketSequence" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    ticket_sequence = Some(field_value)
                }

                if field_info.name == "DestinationTag" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    destination_tag = Some(field_value)
                }

                if field_info.name == "Flags" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    flags = Some(field_value)
                }
            }
            "UInt64" => {
                let _: u32 = binary_parser.read_uint32().unwrap();

                let _: u32 = binary_parser.read_uint32().unwrap();
            }
            "STArray" => {
                let mut bytes = Vec::new();
                while !binary_parser.is_end(None) {
                    let field = binary_parser.read_field().unwrap();
                    if field.name == constants::ARRAY_END_MARKER_NAME {
                        break;
                    }
                    bytes.extend_from_slice(&field.header.to_bytes());

                    let object_value: Vec<u8> = deserialize_object(&mut binary_parser).unwrap();

                    bytes.extend_from_slice(object_value.as_ref());
                    bytes.extend_from_slice(constants::OBJECT_END_MARKER_ARRAY);
                }
                bytes.extend_from_slice(constants::ARRAY_END_MARKER);

                let field_value: STArray = STArray::new(Some(&bytes)).unwrap();

                if field_info.name == "Memos" {
                    fields_and_values.insert(field_info.clone().name, field_info.clone());
                    memos = Some(field_value)
                }
            }
            "STObject" => {
                let _: Vec<u8> = deserialize_object(&mut binary_parser).unwrap();
            }
            _ => {
                return Err(ChainError::InvalidData(format!(
                    "invalid type {}",
                    field_info.associated_type.as_str()
                )))
            }
        }
    }

    Ok(PaymentTransaction {
        fields_and_values,
        common: TransactionCommon {
            account,
            fee,
            sequence,
            account_txn_id,
            last_ledger_sequence,
            memos,
            network_id,
            source_tag,
            signing_pub_key,
            ticket_sequence,
            txn_signature,
        },
        flags,
        amount,
        destination,
        destination_tag,
        invoice_id,
        send_max,
        deliver_min,
    })
}
