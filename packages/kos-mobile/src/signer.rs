use std::vec;

use lwk_signer::bip39::{Language, Mnemonic};
use lwk_wollet::bitcoin::bip32::Xpriv;

use lwk_wollet::bitcoin::Network;
use lwk_wollet::elements_miniscript::ToPublicKey;
use lwk_wollet::elements_miniscript::{
    bitcoin::bip32::{ChildNumber, DerivationPath},
    bitcoin::hashes::{hmac, sha512},
    elements::{bitcoin::bip32::Xpub, secp256k1_zkp::Secp256k1},
    slip77::MasterBlindingKey,
};

use kos::crypto::mnemonic::mnemonic_to_seed;
use lwk_wollet::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use lwk_wollet::secp256k1;
use lwk_wollet::secp256k1::Message;

#[derive(Debug, thiserror::Error, uniffi::Enum)]
pub enum LdError {
    MnemonicError,
    IntanceError,
    SignerError,
    Generic { err: String },
    DerivationError,
    InvalidIndex(u32),
}

impl std::fmt::Display for LdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // LdError::Bip39(e) => write!(f, "{}", e),
            // LdError::Bip32(e) => write!(f, "{}", e),
            LdError::MnemonicError => write!(f, "MnemonicError"),
            LdError::IntanceError => write!(f, "IntanceError"),
            LdError::SignerError => write!(f, "SignerError"),
            LdError::Generic { err } => write!(f, "{err}"),
            LdError::DerivationError => write!(f, "DerivationError"),
            LdError::InvalidIndex(index) => write!(f, "InvalidIndex: {index}"),
        }
    }
}

fn derive_from_mnemonic(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
) -> Result<Vec<u8>, LdError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase).unwrap();

    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let root = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;

    let secp = Secp256k1::new();

    if index >= 0x80000000 {
        return Err(LdError::InvalidIndex(index));
    }

    const BIP85_BIP39_INDEX: ChildNumber = ChildNumber::Hardened { index: 39 };
    let language_index = 0;
    let word_count: u32 = mnemonic.split_whitespace().count() as u32;
    let lang = Language::English;

    let path = DerivationPath::from(vec![
        BIP85_BIP39_INDEX,
        ChildNumber::Hardened {
            index: language_index,
        },
        ChildNumber::from_hardened_idx(word_count).unwrap(),
        ChildNumber::from_hardened_idx(index).unwrap(),
    ]);
    let data = derive(&secp, &root, &path).map_err(|_| LdError::DerivationError)?;
    let len = word_count * 4 / 3;
    let mnemonic = Mnemonic::from_entropy_in(lang, &data[0..len as usize]).unwrap();
    let mnemonic_str = mnemonic.to_string();
    Ok(mnemonic_str.as_bytes().to_vec())
}

fn derive<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
    secp: &Secp256k1<C>,
    root: &Xpriv,
    path: &P,
) -> Result<Vec<u8>, LdError> {
    let bip85_root = root.derive_priv(secp, path).unwrap();
    let derived = bip85_root.derive_priv(secp, &path).unwrap();
    let mut h = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    h.input(&derived.private_key.secret_bytes());
    let data = hmac::Hmac::from_engine(h).to_byte_array();
    Ok(data.to_vec())
}

#[uniffi::export]
pub fn generate_xpub(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();

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
pub fn get_xpub_as_string(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
) -> Result<String, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
    let network = if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Testnet
    };
    let xprv = Xpriv::new_master(network, &seed).map_err(|_| LdError::IntanceError)?;

    let secp = Secp256k1::new();
    Ok(Xpub::from_priv(&secp, &xprv).public_key.to_string())
}

#[uniffi::export]
pub fn derive_xpub(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
    derivation_path: &str,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
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
pub fn slip77_master_blinding_key(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
    let master_blinding_key = MasterBlindingKey::from_seed(&seed);
    Ok(master_blinding_key.as_bytes().to_vec())
}

#[uniffi::export]
pub fn sign_ecdsa_recoverable(
    mnemonic: &str,
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();

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
    is_mainnet: bool,
    index: u32,
    derivation_path: &str,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
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
    index: u32,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
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
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
    msg: Vec<u8>,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
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
    passphrase: &str,
    is_mainnet: bool,
    index: u32,
    msg: Vec<u8>,
    derivation_path: String,
) -> Result<Vec<u8>, LdError> {
    let seed = derive_from_mnemonic(mnemonic, passphrase, is_mainnet, index).unwrap();
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

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn should_generate_xpub() {
        let passphrase = "";
        let is_mainnet = true;
        let xpub = generate_xpub(MNEMONIC, passphrase, is_mainnet, 0).unwrap();
        assert_eq!(xpub.len(), 78);
    }

    #[test]
    fn should_derive_xpub() {
        let passphrase = "";
        let is_mainnet = false;
        let derivation_path = "84'/1'/0'";
        let derived_xpub =
            derive_xpub(MNEMONIC, passphrase, is_mainnet, 0, derivation_path).unwrap();
        print!("{:?}", derived_xpub);
        assert_eq!(derived_xpub.len(), 78);
    }
}
