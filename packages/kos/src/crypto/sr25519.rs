use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use schnorrkel::context::SigningContext;
use schnorrkel::derive::ChainCode;

const SUBSTRATE_CTX: &[u8; 9] = b"substrate";

#[derive(Debug)]
pub enum Sr25519Error {
    ErrDerive,
}

impl Display for Sr25519Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Sr25519Error::ErrDerive => write!(f, "Derive error"),
        }
    }
}

pub trait Sr25519Trait {
    fn public_from_private(pvk: &[u8; 64]) -> Result<Vec<u8>, Sr25519Error>;
    fn sign(msg: &[u8], pvk: &[u8; 64]) -> Result<Vec<u8>, Sr25519Error>;

    fn hard_derive_mini_sk(seed: &[u8; 32], chaincode: &[u8; 32])
        -> Result<[u8; 32], Sr25519Error>;

    fn expand_secret_key(mini_secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), Sr25519Error>;
}

pub struct Sr25519 {}

impl Sr25519Trait for Sr25519 {
    fn public_from_private(pvk: &[u8; 64]) -> Result<Vec<u8>, Sr25519Error> {
        let pvk = schnorrkel::SecretKey::from_bytes(pvk).unwrap();

        let pbk = pvk.to_public().to_bytes().to_vec();
        Ok(pbk)
    }

    fn sign(msg: &[u8], pvk: &[u8; 64]) -> Result<Vec<u8>, Sr25519Error> {
        let pvk = schnorrkel::SecretKey::from_bytes(pvk).map_err(|_| Sr25519Error::ErrDerive)?;

        let pbk = pvk.to_public();
        let ctx = SigningContext::new(SUBSTRATE_CTX).bytes(msg);
        let ctx = schnorrkel::context::attach_rng(ctx, crate::crypto::rng::getrandom_or_panic());
        let sig = pvk.sign(ctx, &pbk);
        Ok(sig.to_bytes().as_slice().to_vec())
    }

    #[allow(clippy::clone_on_copy)]
    fn hard_derive_mini_sk(
        seed: &[u8; 32],
        chaincode: &[u8; 32],
    ) -> Result<[u8; 32], Sr25519Error> {
        let seed =
            schnorrkel::MiniSecretKey::from_bytes(seed).map_err(|_| Sr25519Error::ErrDerive)?;
        let chaincode = ChainCode(chaincode.clone());
        let (new_seed, _) = seed.hard_derive_mini_secret_key(
            Some(chaincode),
            [],
            schnorrkel::ExpansionMode::Ed25519,
        );
        Ok(new_seed.to_bytes())
    }

    fn expand_secret_key(mini_secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), Sr25519Error> {
        let mini_secret = schnorrkel::MiniSecretKey::from_bytes(mini_secret)
            .map_err(|_| Sr25519Error::ErrDerive)?;
        let secret = mini_secret.expand(schnorrkel::ExpansionMode::Ed25519);
        let mut sk = [0; 32];
        let mut nonce = [0; 32];

        let secret = secret.to_bytes();
        sk.copy_from_slice(&secret[0..32]);
        nonce.copy_from_slice(&secret[32..64]);

        Ok((sk, nonce))
    }
}
