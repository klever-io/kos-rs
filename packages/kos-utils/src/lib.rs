pub mod logger;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pack_unpack() {
        let to_serialize = "data to serialize";
        let serialized = pack(&to_serialize).unwrap();
        let deserialized: String = unpack(&serialized).unwrap();
        assert_eq!(to_serialize, deserialized);
    }
}
