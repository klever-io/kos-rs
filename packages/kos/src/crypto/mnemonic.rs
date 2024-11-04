use crate::chains::ChainError;
use crate::crypto::bip32::Bip32Err;
use coins_bip39::{English, Mnemonic};

pub fn generate_mnemonic(count: usize) -> Result<Mnemonic<English>, ChainError> {
    // create rng
    let mut rng = rand::thread_rng();
    // generate mnemonic phrase
    Ok(Mnemonic::<English>::new_with_count(&mut rng, count)
        .map_err(|_| Bip32Err::InvalidMnemonic)?)
}

pub fn validate_mnemonic(phrase: &str) -> Result<(), ChainError> {
    // validate mnemonic phrase
    let _mnemonic: Mnemonic<English> = phrase.parse().map_err(|_| Bip32Err::InvalidMnemonic)?;
    Ok(())
}
