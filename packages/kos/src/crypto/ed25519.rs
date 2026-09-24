use alloc::vec::Vec;
use core::fmt::Display;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::Signer;
use sha2::Sha512;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Ed25519Err {
    ErrDerive,
}

impl Display for Ed25519Err {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Ed25519Err::ErrDerive => write!(f, "Derive error"),
        }
    }
}

pub struct Ed25519 {}

pub trait Ed25519Trait {
    fn public_from_private(pvk: &[u8; 32]) -> Result<Vec<u8>, Ed25519Err>;
    fn sign(pvk: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, Ed25519Err>;
    fn public_from_extended(pvk: &[u8; 64]) -> Result<Vec<u8>, Ed25519Err>;
    fn sign_extended(pvk: &[u8; 64], msg: &[u8]) -> Result<Vec<u8>, Ed25519Err>;
}

impl Ed25519Trait for Ed25519 {
    fn public_from_private(pvk: &[u8; 32]) -> Result<Vec<u8>, Ed25519Err> {
        if pvk.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }
        let mut sk = ed25519_dalek::SecretKey::default();
        sk.copy_from_slice(pvk);
        let pb = ed25519_dalek::SigningKey::from(&sk)
            .verifying_key()
            .to_bytes()
            .to_vec();
        if pb.len() != 32 || pb.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }

        Ok(pb)
    }

    fn public_from_extended(pvk: &[u8; 64]) -> Result<Vec<u8>, Ed25519Err> {
        if pvk.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }
        let vk = ed25519_dalek::VerifyingKey::from(&ExpandedSecretKey::from_bytes(pvk));
        let pb = vk.to_bytes().to_vec();
        if pb.len() != 32 || pb.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }
        Ok(pb)
    }

    fn sign_extended(pvk: &[u8; 64], msg: &[u8]) -> Result<Vec<u8>, Ed25519Err> {
        if pvk.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }
        let expanded = ExpandedSecretKey::from_bytes(pvk);
        let vk = ed25519_dalek::VerifyingKey::from(&ExpandedSecretKey::from_bytes(pvk));
        let sig = ed25519_dalek::hazmat::raw_sign::<Sha512>(&expanded, msg, &vk);
        Ok(sig.to_bytes().as_slice().to_vec())
    }

    fn sign(pvk: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, Ed25519Err> {
        if pvk.iter().all(|&b| b == 0) {
            return Err(Ed25519Err::ErrDerive);
        }
        let mut sk = ed25519_dalek::SecretKey::default();
        sk.copy_from_slice(pvk);
        let sig_key = ed25519_dalek::SigningKey::from(&sk);
        let sig = sig_key.sign(msg);
        Ok(sig.to_bytes().as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_zero_key_rejected() {
        let zero_32 = [0u8; 32];
        let zero_64 = [0u8; 64];
        assert!(Ed25519::public_from_private(&zero_32).is_err());
        assert!(Ed25519::public_from_extended(&zero_64).is_err());
        assert!(Ed25519::sign(&zero_32, b"msg").is_err());
        assert!(Ed25519::sign_extended(&zero_64, b"msg").is_err());
    }
}
