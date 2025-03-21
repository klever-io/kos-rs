use crate::chains::xrp::transactions::{
    transaction_base::TransactionCommon, Serialize, Transaction,
};
use kos::chains::ChainError;

use xrpl::core::{
    binarycodec::{
        definitions::{load_definition_map, DefinitionHandler, FieldInstance},
        types::{Amount, XRPLType},
        Serialization,
    },
    BinarySerializer,
};

#[derive(Debug)]
pub struct TrustSetTransaction {
    pub common: TransactionCommon,
    pub flags: Option<u32>,
    pub limit_amount: Option<Amount>,
    pub quality_in: Option<u32>,
    pub quality_out: Option<u32>,
}

impl TrustSetTransaction {
    pub fn from(buffer: Vec<(FieldInstance, Vec<u8>)>) -> Result<Self, ChainError> {
        let mut limit_amount: Option<Amount> = None;
        let mut quality_in: Option<u32> = None;
        let mut quality_out: Option<u32> = None;
        let mut flags: Option<u32> = None;

        let common: TransactionCommon = TransactionCommon::from(buffer.clone())?;

        for value in buffer {
            match value.0.name.as_str() {
                "Flags" => {
                    flags = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "LimitAmount" => {
                    limit_amount = Some(
                        Amount::new(Some(value.1.as_ref())).map_err(|_| ChainError::DecodeRawTx)?,
                    );
                }
                "QualityIn" => {
                    quality_in = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                "QualityOut" => {
                    quality_out = Some(u32::from_be_bytes(
                        value.1.try_into().map_err(|_| ChainError::DecodeRawTx)?,
                    ));
                }
                _ => {}
            }
        }

        Ok(TrustSetTransaction {
            common,
            flags,
            limit_amount,
            quality_in,
            quality_out,
        })
    }
}

impl Transaction for TrustSetTransaction {
    fn common_mut(&mut self) -> &mut TransactionCommon {
        &mut self.common
    }
}

impl Serialize for TrustSetTransaction {
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

        if let Some(field_instance) = definition_map.get_field_instance("LimitAmount") {
            if let Some(limit_amount) = self.limit_amount.as_ref() {
                fields_and_value
                    .extend_from_slice(&[(field_instance, limit_amount.as_ref().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("QualityIn") {
            if let Some(quality_in) = self.quality_in {
                fields_and_value
                    .extend_from_slice(&[(field_instance, quality_in.to_be_bytes().to_vec())]);
            }
        }

        if let Some(field_instance) = definition_map.get_field_instance("QualityOut") {
            if let Some(quality_out) = self.quality_out {
                fields_and_value
                    .extend_from_slice(&[(field_instance, quality_out.to_be_bytes().to_vec())]);
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
