use kos_crypto::keypair::KeyPair;
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use sp_core::sr25519::Public;
use std::str::FromStr;
use subxt::utils::AccountId32;
use wasm_bindgen::prelude::wasm_bindgen;

const ADDRESS_LEN: usize = 32;
#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[wasm_bindgen(js_name = "DOTAddress")]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Address of a public key.
    pub fn from_public(public: [u8; 32]) -> Address {
        // pubkey to address use first 32 bytes
        Address(public)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0
    }

    /// Address of a keypair.
    pub fn from_keypair(kp: &KeyPair) -> Address {
        Address::from_public(kp.public_key().try_into().unwrap())
    }

    /// As raw 32-byte address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Address from raw 32-byte.
    pub fn from_bytes(raw: &[u8]) -> &Address {
        assert!(raw.len() == ADDRESS_LEN);

        unsafe { std::mem::transmute(&raw[0]) }
    }

    /// To hex address
    pub fn to_hex_address(self) -> String {
        hex::encode(self.0)
    }

    /// to AccountId32
    pub fn to_account_id32(&self) -> AccountId32 {
        AccountId32::from(self.0)
    }
}

impl FromStr for Address {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = Public::from_ss58check_with_version(s).map_err(|_| "Invalid address")?;

        if decoded.0.len() != ADDRESS_LEN {
            return Err("Invalid address length");
        }

        let mut raw = [0u8; ADDRESS_LEN];
        raw.copy_from_slice(&decoded.0);

        Ok(Address(raw))
    }
}

impl ::std::fmt::Display for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let st = Public::from_raw(self.0).to_ss58check_with_version(Ss58AddressFormat::custom(0));

        st.fmt(f)
    }
}
