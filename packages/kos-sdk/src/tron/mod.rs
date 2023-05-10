pub mod address;
use kos_crypto::{public::PublicKey, secret::SecretKey};
use kos_types::error::Error;

#[derive(Debug, Copy, Clone)]
pub struct TRX {}

impl TRX {
    pub fn get_address_from_private_key(private: SecretKey) -> Result<String, Error> {
        Ok(address::Address::from_private(&private).to_string())
    }

    pub fn get_address_from_public_key(public: PublicKey) -> Result<String, Error> {
        Ok(address::Address::from_public(&public).to_string())
    }
}
