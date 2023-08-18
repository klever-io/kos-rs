pub mod options;
pub mod klever {
    include!(concat!(env!("OUT_DIR"), "/klever/proto.rs"));
    include!(concat!(env!("OUT_DIR"), "/klever/proto.serde.rs"));
}

pub mod tron {
    include!(concat!(env!("OUT_DIR"), "/tron/protocol.rs"));
    include!(concat!(env!("OUT_DIR"), "/tron/protocol.serde.rs"));
}

pub fn write_message<M: prost::Message>(message: &M) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(message.encoded_len());
    message.encode(&mut buf).unwrap();
    buf
}

pub fn from_bytes<M: prost::Message + Default>(buffer: Vec<u8>) -> Result<M, prost::DecodeError> {
    let mut r = M::default();
    r.merge(buffer.as_slice())?;
    Ok(r)
}

pub fn clone<M>(msg: &M) -> Result<M, prost::DecodeError>
where
    M: prost::Message + Default,
{
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|_| prost::DecodeError::new("encode error"))?;

    let mut new_msg = M::default();
    new_msg.merge(buf.as_slice())?;

    Ok(new_msg)
}

pub trait TypeUrl {
    fn type_url() -> &'static str;
}

pub fn pack_to_any<M>(msg: M) -> pbjson_types::Any
where
    M: prost::Message + TypeUrl,
{
    pbjson_types::Any {
        type_url: M::type_url().to_owned(),
        value: msg.encode_to_vec().into(),
    }
}

pub fn unpack_from_option_any<M>(msg: &Option<pbjson_types::Any>) -> Option<M>
where
    M: prost::Message + TypeUrl + Default,
{
    match msg {
        Some(any) => unpack_from_any(any),
        _ => None,
    }
}

pub fn unpack_from_any<M>(msg: &pbjson_types::Any) -> Option<M>
where
    M: prost::Message + TypeUrl + Default,
{
    if msg.type_url == M::type_url() {
        Some(M::decode(&msg.value[..]).ok()?)
    } else {
        None
    }
}
