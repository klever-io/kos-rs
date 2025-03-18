use crate::chains::xrp::transactions::{
    transaction_base::TransactionCommon, Serialize, Transaction,
};
use crate::chains::ChainError;

use xrpl::core::{
    binarycodec::{
        definitions::{load_definition_map, DefinitionHandler, FieldInstance},
        types::{account_id::AccountId, Amount, Hash256, PathSet, XRPLType},
        Serialization,
    },
    BinarySerializer,
};

#[derive(Debug)]
pub struct PaymentTransaction {
    pub common: TransactionCommon,
    pub flags: Option<u32>,
    pub amount: Amount,
    pub destination: AccountId,
    pub destination_tag: Option<u32>,
    pub invoice_id: Option<Hash256>,
    pub send_max: Option<Amount>,
    pub deliver_min: Option<Amount>,
    pub paths: Option<PathSet>,
}

impl PaymentTransaction {
    pub fn from(buffer: Vec<(FieldInstance, Vec<u8>)>) -> Result<Self, ChainError> {
        let mut flags: Option<u32> = None; // Some(0);
        let mut amount: Amount = Amount::new(Some(&[0])).unwrap();
        let mut destination: AccountId = AccountId::new(None).unwrap();
        let mut destination_tag: Option<u32> = None;
        let mut invoice_id: Option<Hash256> = None;
        let mut send_max: Option<Amount> = None;
        let mut deliver_min: Option<Amount> = None;
        let mut paths: Option<PathSet> = None;

        let common: TransactionCommon = TransactionCommon::from(buffer.clone())?;

        for value in buffer {
            match value.0.name.as_str() {
                "Flags" => {
                    flags = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                "Amount" => {
                    amount = Amount::new(Some(value.1.as_ref())).unwrap();
                }
                "Destination" => {
                    destination = AccountId::new(Some(value.1.as_ref())).unwrap();
                }
                "DestinationTag" => {
                    destination_tag = Some(u32::from_be_bytes(value.1.try_into().unwrap()));
                }
                "InvoiceID" => {
                    invoice_id = Some(Hash256::new(Some(value.1.as_ref())).unwrap());
                }
                "SendMax" => {
                    send_max = Some(Amount::new(Some(value.1.as_ref())).unwrap());
                }
                "DeliverMin" => {
                    deliver_min = Some(Amount::new(Some(value.1.as_ref())).unwrap());
                }
                "Paths" => {
                    paths = Some(PathSet::new(Some(value.1.as_ref())).unwrap());
                }
                _ => {}
            }
        }

        Ok(PaymentTransaction {
            common,
            flags,
            amount,
            destination,
            destination_tag,
            invoice_id,
            send_max,
            deliver_min,
            paths,
        })
    }
}

impl Transaction for PaymentTransaction {
    fn common_mut(&mut self) -> &mut TransactionCommon {
        &mut self.common
    }
}

impl Serialize for PaymentTransaction {
    fn serialize(&self) -> Result<Vec<u8>, ChainError> {
        let mut fields_and_value: Vec<(FieldInstance, Vec<u8>)> = Vec::new();

        let definition_map: &xrpl::core::binarycodec::definitions::DefinitionMap =
            load_definition_map();

        let common_serialized = self.common.serialize();

        fields_and_value.extend_from_slice(common_serialized.as_ref());

        if let Some(field_instance) = definition_map.get_field_instance("Flags") {
            if let Some(flags) = self.flags {
                fields_and_value
                    .extend_from_slice(&[(field_instance, flags.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("DestinationTag") {
            if let Some(destination_tag) = self.destination_tag {
                fields_and_value
                    .extend_from_slice(&[(field_instance, destination_tag.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Amount") {
            fields_and_value.extend_from_slice(&[(field_instance, self.amount.as_ref().to_vec())]);
        }

        if let Some(field_instance) = definition_map.get_field_instance("Destination") {
            fields_and_value
                .extend_from_slice(&[(field_instance, self.destination.as_ref().to_vec())]);
        }

        if let Some(field_instance) = definition_map.get_field_instance("InvoiceID") {
            if let Some(invoice_id) = self.invoice_id.clone() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, invoice_id.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("SendMax") {
            if let Some(send_max) = self.send_max.clone() {
                fields_and_value.extend_from_slice(&[(field_instance, send_max.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("DeliverMin") {
            if let Some(deliver_min) = self.deliver_min.clone() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, deliver_min.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("Paths") {
            if let Some(paths) = self.paths.clone() {
                fields_and_value.extend_from_slice(&[(field_instance, paths.as_ref().to_vec())]);
            }
        }

        let mut serializer = BinarySerializer::new();

        fields_and_value.sort_by_key(|fv| fv.0.ordinal);
        for fv in fields_and_value {
            serializer.write_field_and_value(fv.0, fv.1.as_ref(), false);
        }

        Ok(serializer)
    }
}
