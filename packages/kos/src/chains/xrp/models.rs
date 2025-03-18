use crate::chains::xrp::constants;
use crate::chains::ChainError;

use xrpl::{
    core::{BinaryParser, Parser},
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
        let field = binary_parser.read_field().unwrap();
        if field.name == constants::OBJECT_END_MARKER_NAME {
            break;
        }

        let length_prefix = binary_parser.read_length_prefix().unwrap();
        let content = binary_parser.read(length_prefix).unwrap();

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
