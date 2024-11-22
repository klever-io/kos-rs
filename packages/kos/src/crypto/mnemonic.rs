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

impl From<coins_bip39::MnemonicError> for ChainError {
    fn from(_: coins_bip39::MnemonicError) -> Self {
        Self::InvalidMnemonic
    }
}
