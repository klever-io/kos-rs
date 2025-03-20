use crate::chains::ChainError;
use coins_bip39::{English, Mnemonic};

pub fn generate_mnemonic(count: usize) -> Result<Mnemonic<English>, ChainError> {
    // create rng
    let mut rng = rand::thread_rng();
    // generate mnemonic phrase
    Ok(Mnemonic::<English>::new_with_count(&mut rng, count)?)
}

pub fn validate_mnemonic(phrase: &str) -> Result<(), ChainError> {
    // validate mnemonic phrase
    let _mnemonic: Mnemonic<English> = phrase.parse()?;
    Ok(())
}

pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Vec<u8>, ChainError> {
    let _mnemonic: Mnemonic<English> = phrase.parse()?;
    Ok(
        _mnemonic.to_seed(Some(passphrase))
            .map(|seed| seed.to_vec())
            .map_err(|_| ChainError::InvalidMnemonic)?,
    )
}

impl From<coins_bip39::MnemonicError> for ChainError {
    fn from(_: coins_bip39::MnemonicError) -> Self {
        Self::InvalidMnemonic
    }
}
