use crate::chains::ChainError;
use alloc::vec;
use alloc::vec::Vec;
use coins_bip39::mnemonic::Entropy;
use coins_bip39::{English, Mnemonic};
use rand::Rng;

fn word_count_to_entropy_bytes(count: usize) -> Result<usize, ChainError> {
    match count {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        _ => Err(ChainError::InvalidMnemonic),
    }
}

#[cfg(feature = "not-ksafe")]
pub fn generate_mnemonic(count: usize) -> Result<Mnemonic<English>, ChainError> {
    let entropy_bytes = word_count_to_entropy_bytes(count)?;
    let mut buf = vec![0u8; entropy_bytes];
    rand::rng().fill_bytes(&mut buf[..]);
    let entropy = Entropy::from_slice(&buf)?;
    Ok(Mnemonic::<English>::new_from_entropy(entropy))
}

pub fn validate_mnemonic(phrase: &str) -> Result<(), ChainError> {
    let _mnemonic: Mnemonic<English> = phrase.parse()?;
    Ok(())
}

pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Vec<u8>, ChainError> {
    let mnemonic: Mnemonic<English> = phrase.parse()?;
    mnemonic
        .to_seed(Some(passphrase))
        .map(|seed| seed.to_vec())
        .map_err(|_| ChainError::InvalidMnemonic)
}

impl From<coins_bip39::MnemonicError> for ChainError {
    fn from(_: coins_bip39::MnemonicError) -> Self {
        Self::InvalidMnemonic
    }
}
