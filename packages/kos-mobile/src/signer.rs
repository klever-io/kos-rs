use lwk_wollet::bitcoin::bip32::Xpriv;

use lwk_wollet::bitcoin::Network;
use lwk_wollet::elements_miniscript:: {
    bitcoin::bip32::DerivationPath,
    elements::{
        bitcoin::bip32::Xpub,
        secp256k1_zkp::Secp256k1,
    }
};

use kos::crypto::mnemonic::mnemonic_to_seed;


#[derive(Debug, thiserror::Error, uniffi::Enum)]
pub enum LdError{
    MnemonicError,
    IntanceError,
}

impl std::fmt::Display for LdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // LdError::Bip39(e) => write!(f, "{}", e),
            // LdError::Bip32(e) => write!(f, "{}", e),
            LdError::MnemonicError => write!(f, "MnemonicError"),
            LdError::IntanceError => write!(f, "IntanceError"),
        }
    }
}

#[uniffi::export]
pub fn generate_xpub(mnemonic: &str, passphrase: &str, is_mainnet: bool) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet { Network::Bitcoin } else { Network::Testnet };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;

    let secp = Secp256k1::new();    
    Ok(Xpub::from_priv(&secp, &xprv).encode().to_vec())
}

#[uniffi::export]
pub fn derive_xpub(mnemonic: &str, passphrase: &str, is_mainnet: bool, derivation_path: &str) -> Result<Vec<u8>, LdError> {
    // let xpub = Xpub::decode(xpub).map_err(|_| LdError::IntanceError)?;
    // let secp = Secp256k1::new();
    // let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
    // print!("{:?}", der);
    // let derived = xpub.derive_pub(&secp, &der).map_err(|_| LdError::IntanceError)?;
    // print!("{:?}", derived);
    // Ok(derived.encode().to_vec()) 

    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet { Network::Bitcoin } else { Network::Testnet };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;
    let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
    let secp = Secp256k1::new();
    let derived = xprv.derive_priv(&secp, &der).map_err(|_| LdError::IntanceError)?;
    Ok(Xpub::from_priv(&secp, &derived).encode().to_vec())
}

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::signer::generate_xpub;
    use crate::signer::derive_xpub;
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn should_generate_xpub() {
        let passphrase = "";
        let is_mainnet = true;
        let xpub = generate_xpub(MNEMONIC, passphrase, is_mainnet).unwrap();
        assert_eq!(xpub.len(), 78); 
    }

    #[test]
    fn should_derive_xpub() {
        let passphrase = "";
        let is_mainnet = true;
        let derivation_path = "84'/1'/0'";
        let derived_xpub = derive_xpub(MNEMONIC, passphrase, is_mainnet, derivation_path).unwrap();
        print!("{:?}", derived_xpub);
        assert_eq!(derived_xpub.len(), 78); 
    }
}