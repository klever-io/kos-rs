use crate::chains::xrp::constants;
use kos::chains::ChainError;

use xrpl::{
    core::{
        binarycodec::{
            definitions::FieldInstance,
            types::{
                account_id::AccountId, amount::Amount, blob::Blob, xchain_bridge::XChainBridge,
                Currency, Hash128, Hash160, Hash256, PathSet, STArray, XRPLType,
            },
        },
        BinaryParser, Parser,
    },
    utils::ToBytes,
};

pub fn encode_variable_length(length: usize) -> Result<Vec<u8>, ChainError> {
    let mut len_bytes = [0u8; 3];
    if length <= 192 {
        len_bytes[0] = length as u8;
        Ok(len_bytes[0..1].to_vec())
    } else if length <= 12480 {
        let length = length - 193;
        len_bytes[0] = 193 + ((length >> 8) as u8);
        len_bytes[1] = (length & 0xff) as u8;
        Ok(len_bytes[0..2].to_vec())
    } else if length <= 918744 {
        let length = length - 12481;
        len_bytes[0] = 241 + ((length >> 16) as u8);
        len_bytes[1] = ((length >> 8) & 0xff) as u8;
        len_bytes[2] = (length & 0xff) as u8;
        Ok(len_bytes[0..3].to_vec())
    } else {
        Err(ChainError::InvalidData("Overflow".to_string()))
    }
}

pub fn deserialize_object(binary_parser: &mut BinaryParser) -> Result<Vec<u8>, ChainError> {
    let mut sink: Vec<Vec<u8>> = Vec::new();
    while !binary_parser.is_end(None) {
        let field = binary_parser
            .read_field()
            .map_err(|_| ChainError::DecodeRawTx)?;
        if field.name == constants::OBJECT_END_MARKER_NAME {
            break;
        }

        let length_prefix = binary_parser
            .read_length_prefix()
            .map_err(|_| ChainError::DecodeRawTx)?;
        let content = binary_parser
            .read(length_prefix)
            .map_err(|_| ChainError::DecodeRawTx)?;

        let teste = vec![field.header.to_bytes()];
        sink.extend_from_slice(&teste);

        if field.is_vl_encoded {
            let vl = encode_variable_length(length_prefix)?;
            sink.push(vl);
        }
        sink.push(content);
        if field.name == constants::OBJECT_NAME {
            sink.push(constants::OBJECT_END_MARKER_BYTE.to_vec());
        }
    }
    let concatenated_sink: Vec<u8> = sink.into_iter().flatten().collect();
    Ok(concatenated_sink)
}

pub fn decode_transaction(buffer: Vec<u8>) -> Result<Vec<(FieldInstance, Vec<u8>)>, ChainError> {
    let mut fields_and_value: Vec<(FieldInstance, Vec<u8>)> = Vec::new();

    let mut binary_parser = xrpl::core::BinaryParser::from(buffer);
    while !binary_parser.is_end(None) {
        let field_info = binary_parser
            .read_field()
            .map_err(|_| ChainError::DecodeRawTx)?;

        match field_info.clone().associated_type.as_str() {
            "AccountID" => {
                let field_value: AccountId = binary_parser
                    .read_field_value(&field_info.clone())
                    .map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Amount" => {
                let length_prefix = binary_parser.peek().unwrap_or([64]);
                let size = u8::from_be_bytes(length_prefix);
                let mut bytes = 8;
                if size != 64 {
                    bytes = 48
                }

                let content = binary_parser
                    .read(bytes as usize)
                    .map_err(|_| ChainError::DecodeRawTx)?;

                let field_value: Amount =
                    Amount::new(Some(&content)).map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Blob" => {
                let length_prefix = binary_parser
                    .read_length_prefix()
                    .map_err(|_| ChainError::DecodeRawTx)?;
                let content = binary_parser
                    .read(length_prefix)
                    .map_err(|_| ChainError::DecodeRawTx)?;

                let field_value: Blob =
                    Blob::new(Some(&content)).map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Currency" => {
                let field_value: Currency = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Hash128" => {
                let field_value: Hash128 = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Hash160" => {
                let field_value: Hash160 = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "Hash256" => {
                let field_value: Hash256 = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "XChainClaimID" => {
                let field_value: XChainBridge = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            "UInt8" => {
                let field_value: u8 = binary_parser
                    .read_uint8()
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value
                    .extend_from_slice(&[(field_info, field_value.to_be_bytes().to_vec())])
            }
            "UInt16" => {
                let field_value: u16 = binary_parser
                    .read_uint16()
                    .map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value
                    .extend_from_slice(&[(field_info, field_value.to_be_bytes().to_vec())])
            }
            "UInt32" => {
                let field_value: u32 = binary_parser
                    .read_uint32()
                    .map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value
                    .extend_from_slice(&[(field_info, field_value.to_be_bytes().to_vec())]);
            }
            "UInt64" => {
                let result = binary_parser.read(8).map_err(|_| ChainError::DecodeRawTx)?;
                let field_value =
                    u64::from_be_bytes(result.try_into().map_err(|_| ChainError::DecodeRawTx)?);
                fields_and_value
                    .extend_from_slice(&[(field_info, field_value.to_be_bytes().to_vec())]);
            }
            "STArray" => {
                let mut bytes = Vec::new();
                while !binary_parser.is_end(None) {
                    let field = binary_parser
                        .read_field()
                        .map_err(|_| ChainError::DecodeRawTx)?;
                    if field.name == constants::ARRAY_END_MARKER_NAME {
                        break;
                    }
                    bytes.extend_from_slice(&field.header.to_bytes());

                    let object_value: Vec<u8> = deserialize_object(&mut binary_parser)
                        .map_err(|_| ChainError::DecodeRawTx)?;

                    bytes.extend_from_slice(object_value.as_ref());
                    bytes.extend_from_slice(constants::OBJECT_END_MARKER_ARRAY);
                }
                bytes.extend_from_slice(constants::ARRAY_END_MARKER);

                let field_value: STArray =
                    STArray::new(Some(&bytes)).map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())]);
            }
            "STObject" => {
                let field_value: Vec<u8> =
                    deserialize_object(&mut binary_parser).map_err(|_| ChainError::DecodeRawTx)?;
                fields_and_value.extend_from_slice(&[(field_info, field_value)]);
            }
            "PathSet" => {
                let field_value: PathSet = binary_parser
                    .read_field_value(&field_info)
                    .map_err(|_| ChainError::DecodeRawTx)?;

                fields_and_value.extend_from_slice(&[(field_info, field_value.as_ref().to_vec())])
            }
            _ => {
                return Err(ChainError::InvalidData(format!(
                    "invalid type {}",
                    field_info.associated_type.as_str()
                )))
            }
        }
    }

    Ok(fields_and_value)
}
