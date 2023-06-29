use kos_crypto::mnemonic::generate_mnemonic;
use kos_types::error::Error;

#[no_mangle]
pub fn generate_mnemonic_phrase(count: usize) -> Result<String, Error> {
    Ok(generate_mnemonic(count)?.to_phrase())
}
