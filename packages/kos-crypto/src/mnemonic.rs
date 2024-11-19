use kos_types::error::Error;

use coins_bip39::{English, Mnemonic};

pub fn generate_mnemonic(count: usize) -> Result<Mnemonic<English>, Error> {
    // create rng
    let mut rng = rand::thread_rng();
    // generate mnemonic phrase
    Ok(Mnemonic::<English>::new_with_count(&mut rng, count)?)
}

pub fn validate_mnemonic(phrase: &str) -> Result<(), Error> {
    // validate mnemonic phrase
    let _mnemonic: Mnemonic<English> = phrase.parse()?;
    Ok(())
}
