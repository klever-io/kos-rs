use kos_types::error::Error;
use serde::{Deserialize, Serialize};

pub fn pack<T>(t: &T) -> Result<Vec<u8>, Error>
where
    T: Serialize + ?Sized,
{
    postcard::to_stdvec(t).map_err(|e| Error::InvalidString(e.to_string()))
}

pub fn unpack<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    postcard::from_bytes(bytes).map_err(|e| Error::InvalidString(e.to_string()))
}
