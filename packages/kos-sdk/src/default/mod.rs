use kos_crypto::{public::PublicKey, secret::SecretKey};
use kos_types::error::Error;

#[derive(Debug, Copy, Clone)]
pub struct NONE;

impl NONE {
    pub fn get_address_from_private_key(_private: SecretKey) -> Result<String, Error> {
        Err(Error::UnsupportedChain("NONE".into()))
    }

    pub fn get_address_from_public_key(_public: PublicKey) -> Result<String, Error> {
        Err(Error::UnsupportedChain("NONE".into()))
    }
}
