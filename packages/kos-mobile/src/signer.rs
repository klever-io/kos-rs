use lwk_wollet::bitcoin::bip32::Xpriv;

use lwk_wollet::bitcoin::Network;
use lwk_wollet::elements_miniscript::ToPublicKey;
use lwk_wollet::elements_miniscript::{
    bitcoin::bip32::DerivationPath,
    elements::{bitcoin::bip32::Xpub, secp256k1_zkp::Secp256k1},
    slip77::MasterBlindingKey,
};

use kos::crypto::mnemonic::mnemonic_to_seed;
use lwk_wollet::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use lwk_wollet::secp256k1::Message;

#[derive(Debug, thiserror::Error, uniffi::Enum)]
pub enum LdError {
    MnemonicError,
    IntanceError,
    SignerError,
    Generic { err: String },
}

impl std::fmt::Display for LdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // LdError::Bip39(e) => write!(f, "{}", e),
            // LdError::Bip32(e) => write!(f, "{}", e),
            LdError::MnemonicError => write!(f, "MnemonicError"),
            LdError::IntanceError => write!(f, "IntanceError"),
            LdError::SignerError => write!(f, "SignerError"),
            LdError::Generic { err } => write!(f, "{}", err),
        }
    }
}

#[uniffi::export]
pub fn generate_xpub(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;

    let secp = Secp256k1::new();
    Ok(Xpub::from_priv(&secp, &xprv).encode().to_vec())
}

#[uniffi::export]
pub fn derive_xpub(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    derivation_path: &str,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;
    let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
    let secp = Secp256k1::new();
    let derived = xprv
        .derive_priv(&secp, &der)
        .map_err(|_| LdError::IntanceError)?;
    Ok(Xpub::from_priv(&secp, &derived).encode().to_vec())
}

#[uniffi::export]
pub fn slip77_master_blinding_key(mnemonic: &str, passphrase: &str) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let master_blinding_key = MasterBlindingKey::from_seed(&seed);
    Ok(master_blinding_key.as_bytes().to_vec())
}

#[uniffi::export]
pub fn sign_ecdsa_recoverable(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();

    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };

    let secp = Secp256k1::new();
    let keypair = Xpriv::new_master(network, &seed)
        .map_err(|_| LdError::SignerError)?
        .to_keypair(&secp);
    let s = msg.as_slice();
    let msg: Message = Message::from_digest_slice(s).map_err(|_| LdError::SignerError)?;
    let recoverable_sig = secp.sign_ecdsa_recoverable(&msg, &keypair.secret_key());
    let (recovery_id, sig) = recoverable_sig.serialize_compact();
    let mut complete_signature = vec![31 + recovery_id.to_i32() as u8];
    complete_signature.extend_from_slice(&sig);
    Ok(complete_signature)
}

#[uniffi::export]
pub fn hmac_sha256(
    mnemonic: &str,
    passphrase: &str,
    derivation_path: &str,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let xprv = Xpriv::new_master(Network::Bitcoin, &seed).map_err(|_| LdError::IntanceError)?;
    let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
    let priv_key = xprv
        .derive_priv(&Secp256k1::new(), &der)
        .map_err(|_| LdError::IntanceError)?;
    let mut engine = HmacEngine::<sha256::Hash>::new(priv_key.to_priv().to_bytes().as_slice());

    engine.input(msg.as_slice());
    Ok(Hmac::<sha256::Hash>::from_engine(engine)
        .as_byte_array()
        .to_vec())
}

#[uniffi::export]
pub fn ecies_encrypt(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;
    let secp = Secp256k1::new();
    let keypair = xprv.to_keypair(&secp);
    let rc_pub = keypair.public_key().to_public_key().to_bytes();
    ecies::encrypt(&rc_pub, &msg).map_err(|err| LdError::Generic {
        err: format!("Could not encrypt data: {err}"),
    })
}

#[uniffi::export]
pub fn ecies_decrypt(
    mnemonic: &str,
    is_mainnet: bool,
    passphrase: &str,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;
    let rc_prv = xprv.to_priv().to_bytes();
    ecies::decrypt(&rc_prv, &msg).map_err(|err| LdError::Generic {
        err: format!("Could not decrypt data: {err}"),
    })
}

#[uniffi::export]
fn sign_ecdsa(
    mnemonic: &str,
    is_mainnet: bool,
    passphrase: &str,
    msg: Vec<u8>,
    derivation_path: String,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;
    let secp = Secp256k1::new();
    let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
    let ext_derived = xprv
        .derive_priv(&secp, &der)
        .map_err(|_| LdError::IntanceError)?;
    let sig = secp.sign_ecdsa_low_r(
        &Message::from_digest(msg.try_into().map_err(|_| LdError::SignerError)?),
        &ext_derived.private_key,
    );
    Ok(sig.serialize_der().to_vec())
}

#[cfg(test)]
mod tests {
    use crate::signer::derive_xpub;
    use crate::signer::generate_xpub;
    use crate::*;
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
        let is_mainnet = false;
        let derivation_path = "84'/1'/0'";
        let derived_xpub = derive_xpub(MNEMONIC, passphrase, is_mainnet, derivation_path).unwrap();
        print!("{:?}", derived_xpub);
        assert_eq!(derived_xpub.len(), 78);
    }
}
