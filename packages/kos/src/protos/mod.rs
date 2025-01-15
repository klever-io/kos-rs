pub mod generated;
use crate::crypto::base64::{simple_base64_decode, simple_base64_encode};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use tiny_json_rs::mapper;
use tiny_json_rs::mapper::Value;
use tiny_json_rs::serializer::DecodeError;
use tiny_json_rs::serializer::{Deserialize, Serialize};

#[allow(dead_code)]
pub trait TypeUrl {
    fn type_url() -> &'static str;
}

// Implement serialization for `Any`
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Any {
    #[prost(string, tag = "1")]
    pub type_url: String,
    // This field will hold the actual byte array
    #[prost(bytes, tag = "2")]
    pub value: Vec<u8>,
}

impl Any {
    // Encodes the value field to a base64 string
    pub fn encode_to_base64(&self) -> String {
        simple_base64_encode(&self.value)
    }

    // Decodes a base64 string to the value field
}

// Implement serde's Serialize for Any
// This is a simplified example and you'll likely need a more comprehensive implementation.
impl Serialize for Any {
    fn serialize(&self) -> Value {
        let mut object = mapper::Object::new();
        object.insert("type_url".to_string(), self.type_url.serialize());
        object.insert("value".to_string(), self.encode_to_base64().serialize());
        Value::Object(object)
    }
}

impl Deserialize for Any {
    fn deserialize(value: Option<&Value>) -> Result<Self, DecodeError> {
        let value = match value {
            None => return Err(DecodeError::UnexpectedType),
            Some(v) => v,
        };

        let key = value.get_value::<String>("type_url")?;
        let value = value.get_value::<String>("value")?;

        let value = simple_base64_decode(&value)
            .map_err(|_| DecodeError::ParseError("Error encoding Any".to_string()))?;
        Ok(Any {
            type_url: key,
            value,
        })
    }
}
