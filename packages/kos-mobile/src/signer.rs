use crate::runtime::rt;
use std::str::FromStr;
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
    let xpub = Xpub::from_priv(&secp, &xprv);
    println!("XPUB: {:?}", xpub.to_string());
    Ok(Xpub::from_priv(&secp, &xprv).encode().to_vec())
}

#[uniffi::export]
pub async fn generate_xpub_mpc(secret_share: &str) -> Result<Vec<u8>, LdError> {
    let result = rt()
        .block_on(async { kos_mpc::derive_xpub(secret_share).await })
        .map_err(|_| LdError::IntanceError)?;

    let xpub = Xpub::from_str(&result).unwrap();
    Ok(xpub.encode().to_vec())
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
    let xpub = Xpub::from_priv(&secp, &derived);

    println!("Derived XPUB: {:?}", xpub.to_string());
    Ok(xpub.encode().to_vec())
}

// #[uniffi::export]
// pub async fn derive_xpub_mpc(
//     secret_share: &str,
//     derivation_path: &str,
// ) -> Result<Vec<u8>, LdError> {
//     // let result = rt()
//     //     .block_on(async {
//     //         kos_mpc::derive_public_key_xpub(secret_share, derivation_path, true).await
//     //     })
//     //     .map_err(|_| LdError::IntanceError)?;

//     // let result = rt()
//     //     .block_on(async { kos_mpc::derive_xpub(secret_share).await })
//     //     .map_err(|_| LdError::IntanceError)?;

//     // let result = kos_mpc::derive_xpub(secret_share)
//     //     .await
//     //     .map_err(|_| LdError::IntanceError)?;

//     let mut xpub = bip32::XPub::from_str("xpub661MyMwAqRbcFdZUMdZbZMEtbv8jADWz6WPcayTd4CPXVPf2421BiggfaA3VToE13NJYRD4VptyF4t8jM7pCrvpRfEDi46bc8GKs5kVfbZR").unwrap();

//     // let derivation_path_obj = bip32::DerivationPath::from_str(derivation_path)
//     //     .map_err(|e| LdError::Generic { err: e.to_string() })?;

//     let derivation_path_parts = derivation_path.split('/');

//     derivation_path_parts.into_iter().for_each(|part| {
//         if part == "m" || part == "" {
//             return;
//         }

//         let is_hardened = part.ends_with('\'');
//         let index_str = if is_hardened {
//             &part[..part.len() - 1]
//         } else {
//             part
//         };

//         let index: u32 = index_str.parse().unwrap();
//         let child = if is_hardened {
//             bip32::ChildNumber::new(index, false).unwrap()
//         } else {
//             bip32::ChildNumber::new(index, false).unwrap()
//         };

//         if child.is_hardened() {
//             panic!("Hardened derivation is not supported for xpub derivation");
//         }

//         xpub = xpub
//             .derive_child(child)
//             .map_err(|e| LdError::Generic { err: e.to_string() })
//             .unwrap();
//     });
//     // derivation_path_obj.iter().for_each(|child| {
//     //     if child.is_hardened() {
//     //         panic!("Hardened derivation is not supported for xpub derivation");
//     //     }

//     //     xpub = xpub
//     //         .derive_child(child)
//     //         .map_err(|e| LdError::Generic { err: e.to_string() })
//     //         .unwrap();
//     // });

//     // let child_one = bip32::ChildNumber::new(84, false).unwrap();
//     // let child_two = bip32::ChildNumber::new(1, false).unwrap();
//     // let child_three = bip32::ChildNumber::new(0, false).unwrap();

//     // let xpub_child = xpub
//     //     .derive_child(child_one)
//     //     .and_then(|x| x.derive_child(child_two))
//     //     .and_then(|x| x.derive_child(child_three))
//     //     .map_err(|_| LdError::IntanceError)?;

//     let mut buffer = [0u8; 112];

//     let xpub_base58 = xpub
//         .to_extended_key(bip32::Prefix::TPUB)
//         .write_base58(&mut buffer)
//         .map_err(|e| LdError::Generic { err: e.to_string() })?;

//     // println!("xpub: {}", std::str::from_utf8(&buffer.clone()).unwrap());

//     // let buffer_clone = buffer.clone();
//     // let xpub_string = std::str::from_utf8(&buffer_clone).unwrap();
//     println!("xpub: {}", xpub_base58.clone());
//     let xpub_real: Xpub =
//         Xpub::from_str(xpub_base58).map_err(|e| LdError::Generic { err: e.to_string() })?;

//     Ok(xpub_real.encode().to_vec())

//     // let xpub: Xpub = Xpub::from_str(&result).unwrap();

//     // let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
//     // let secp = Secp256k1::new();

//     // let xpub_derived = xpub
//     //     .derive_pub(&secp, &der)
//     //     .map_err(|e| LdError::Generic { err: e.to_string() })?;

//     // Ok(xpub_derived.encode().to_vec())
// }

// #[uniffi::export]
// pub async fn derive_xpub_mpc(
//     secret_share: &str,
//     derivation_path: &str,
// ) -> Result<Vec<u8>, LdError> {
//     let xpub: Xpub = Xpub::from_str("xpub661MyMwAqRbcFdZUMdZbZMEtbv8jADWz6WPcayTd4CPXVPf2421BiggfaA3VToE13NJYRD4VptyF4t8jM7pCrvpRfEDi46bc8GKs5kVfbZR").unwrap();

//     let der: DerivationPath = derivation_path.parse().map_err(|_| LdError::IntanceError)?;
//     let secp = Secp256k1::new();

//     let xpub_derived = xpub
//         .derive_pub(&secp, &der)
//         .map_err(|e| LdError::Generic { err: e.to_string() })?;

//     println!("Derived XPUB: {:?}", xpub_derived.to_string());

//     Ok(xpub_derived.encode().to_vec())
// }

// #[uniffi::export]
// pub async fn derive_xpub_mpc(
//     secret_share: &str,
//     derivation_path: &str,
// ) -> Result<Vec<u8>, LdError> {
//     let mut xpub = bip32::XPub::from_str("xpub661MyMwAqRbcFdZUMdZbZMEtbv8jADWz6WPcayTd4CPXVPf2421BiggfaA3VToE13NJYRD4VptyF4t8jM7pCrvpRfEDi46bc8GKs5kVfbZR").unwrap();

//     let derivation_path_parts = derivation_path.split('/');

//     derivation_path_parts.into_iter().for_each(|part| {
//         if part == "m" || part == "" {
//             return;
//         }

//         let is_hardened = part.ends_with('\'');
//         let index_str = if is_hardened {
//             &part[..part.len() - 1]
//         } else {
//             part
//         };

//         let index: u32 = index_str.parse().unwrap();
//         let child = if is_hardened {
//             bip32::ChildNumber::new(index, false).unwrap()
//         } else {
//             bip32::ChildNumber::new(index, false).unwrap()
//         };

//         if child.is_hardened() {
//             panic!("Hardened derivation is not supported for xpub derivation");
//         }

//         xpub = xpub
//             .derive_child(child)
//             .map_err(|e| LdError::Generic { err: e.to_string() })
//             .unwrap();
//     });

//     let mut buffer = [0u8; 112];

//     let xpub_base58 = xpub
//         .to_extended_key(bip32::Prefix::XPUB)
//         .write_base58(&mut buffer)
//         .map_err(|e| LdError::Generic { err: e.to_string() })?;

//     println!("xpub: {}", xpub_base58.clone());
//     let xpub_real: Xpub =
//         Xpub::from_str(xpub_base58).map_err(|e| LdError::Generic { err: e.to_string() })?;

//     Ok(xpub_real.encode().to_vec())
// }

#[uniffi::export]
pub async fn derive_xpub_mpc(
    secret_share: &str,
    derivation_path: &str,
) -> Result<Vec<u8>, LdError> {
    let mut xpub_original = bip32::XPub::from_str("xpub661MyMwAqRbcFdZUMdZbZMEtbv8jADWz6WPcayTd4CPXVPf2421BiggfaA3VToE13NJYRD4VptyF4t8jM7pCrvpRfEDi46bc8GKs5kVfbZR").unwrap();

    // xpub_original = xpub_original
    //     .derive_child(bip32::ChildNumber::new(84, false).unwrap())
    //     .and_then(|x| x.derive_child(bip32::ChildNumber::new(1, false).unwrap()))
    //     .and_then(|x| x.derive_child(bip32::ChildNumber::new(0, false).unwrap()))
    //     .unwrap();

    let xpub_str = xpub_original.to_string(bip32::Prefix::XPUB);

    println!("xpub: {}", xpub_str);

    let xpub = Xpub::from_str(&xpub_str).map_err(|e| LdError::Generic { err: e.to_string() })?;

    Ok(xpub.encode().to_vec())
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
pub async fn sign_ecdsa_recoverable_mpc(
    secret_share: &str,
    key_id: &str,
    msg: Vec<u8>,
    derivation_path: String,
) -> Result<Vec<u8>, LdError> {
    let result = rt()
        .block_on(async {
            kos_mpc::sign(secret_share, key_id, &derivation_path, &msg, "ecdsa").await
        })
        .map_err(|_| LdError::IntanceError)?;

    Ok(result)
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

#[uniffi::export]
fn sign_ecdsa_mpc(
    secret_share: &str,
    key_id: &str,
    msg: Vec<u8>,
    derivation_path: String,
) -> Result<Vec<u8>, LdError> {
    let result = rt()
        .block_on(async { kos_mpc::sign_der(secret_share, key_id, &derivation_path, &msg).await })
        .map_err(|_| LdError::IntanceError)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kos::test_utils::get_test_mnemonic;

    use crate::signer::derive_xpub;
    use crate::signer::derive_xpub_mpc;
    use crate::signer::generate_xpub;

    fn get_ecdsa_secret_share() -> String {
        std::env::var("ECDSA_SECRET_SHARE").unwrap()
    }

    fn get_ecdsa_key_id() -> String {
        std::env::var("ECDSA_KEY_ID").unwrap()
    }

    fn get_ed25519_secret_share() -> String {
        std::env::var("ED25519_SECRET_SHARE").unwrap()
    }

    fn get_ed25519_key_id() -> String {
        std::env::var("ED25519_KEY_ID").unwrap()
    }

    #[test]
    fn should_generate_xpub() {
        let passphrase = "";
        let is_mainnet = true;
        let xpub = generate_xpub(get_test_mnemonic().as_str(), passphrase, is_mainnet, 0).unwrap();

        // XPUB: "xpub661MyMwAqRbcFdZUMdZbZMEtbv8jADWz6WPcayTd4CPXVPf2421BiggfaA3VToE13NJYRD4VptyF4t8jM7pCrvpRfEDi46bc8GKs5kVfbZR"
        // XPUB: "0488b21e0000000000000000006d51c3dc3c6140e4d28d6f5eaff1920d1b4f77ffbb4ed260466bab72942eab15026fba99626cde7d7611e09ce5aa674ed8ba049f9a3c80d216836453be01ff7f27"
        assert_eq!(xpub.len(), 78);
    }

    #[test]
    fn should_derive_xpub() {
        let passphrase = "";
        let is_mainnet = true;
        let derivation_path = "";
        let derived_xpub = derive_xpub(
            get_test_mnemonic().as_str(),
            passphrase,
            is_mainnet,
            0,
            derivation_path,
        )
        .unwrap();

        /*
        Derived XPUB: "xpub6CZfpt5KFz6bgEjrgm4M88NKAtEeitmdEknoVS5R2xPf8nZ3bb5qqdwcEppMrnYeJ3jvicdcAWjPUT4NDmmFHcPSCVUU3V99ukbQmy4qFAA"
        XPUB: "0488b21e037c17550f80000000ac559fae263ac1f6f1fdb9e02e10b797d864edd1dcb49eefc8ca94218d31a47403c7f6aefdec0ddd01a55665ec7f9970031881e295f267f12f2bc4039b49a2b9d9"
         */
        println!("XPUB: {:?}", hex::encode(derived_xpub.clone()));
        print!("{:?}", derived_xpub);
        assert_eq!(derived_xpub.len(), 78);
    }

    #[tokio::test]
    async fn should_derive_xpub_mpc() {
        let derivation_path = "";
        let derived_xpub = derive_xpub_mpc(get_ecdsa_secret_share().as_str(), derivation_path)
            .await
            .map_err(|e| {
                println!("Error: {}", e);
                e
            })
            .unwrap();

        // xpub: xpub6DK1trPmHvSPq5ETdFZGbB7ePu3vxzx8Rk1FKproQuQMScB6VcwAvSc42kKntsWzNwDcjqtCUYVXp2thrgmqrmqbsWinHzcpCYvQJNYu98y
        // XPUB: "0488b21e03e1c4aa4e000000007c87cff2ae24df9228131de6f0ad46c9b212a0100fe07638bb13244b46a5edf203a3e3fe32b21b3c9184b8c9fd37866c69600dd57b915200ef9709281d64d25a59"

        /*
        Derived XPUB: "xpub6DK1trPmHvSPq5ETdFZGbB7ePu3vxzx8Rk1FKproQuQMScB6VcwAvSc42kKntsWzNwDcjqtCUYVXp2thrgmqrmqbsWinHzcpCYvQJNYu98y"
        XPUB: "0488b21e03e1c4aa4e000000007c87cff2ae24df9228131de6f0ad46c9b212a0100fe07638bb13244b46a5edf203a3e3fe32b21b3c9184b8c9fd37866c69600dd57b915200ef9709281d64d25a59"
         */

        /*
        xpub: xpub6DK1trPmHvSPq5ETdFZGbB7ePu3vxzx8Rk1FKproQuQMScB6VcwAvSc42kKntsWzNwDcjqtCUYVXp2thrgmqrmqbsWinHzcpCYvQJNYu98y
        XPUB: "0488b21e03e1c4aa4e000000007c87cff2ae24df9228131de6f0ad46c9b212a0100fe07638bb13244b46a5edf203a3e3fe32b21b3c9184b8c9fd37866c69600dd57b915200ef9709281d64d25a59"
         */

        /*
        xpub: xpub6DK1trPmHvSPq5ETdFZGbB7ePu3vxzx8Rk1FKproQuQMScB6VcwAvSc42kKntsWzNwDcjqtCUYVXp2thrgmqrmqbsWinHzcpCYvQJNYu98y
        XPUB: "0488b21e03e1c4aa4e000000007c87cff2ae24df9228131de6f0ad46c9b212a0100fe07638bb13244b46a5edf203a3e3fe32b21b3c9184b8c9fd37866c69600dd57b915200ef9709281d64d25a59"
        */

        println!("XPUB: {:?}", hex::encode(derived_xpub.clone()));
        print!("{:?}", derived_xpub);
        assert_eq!(derived_xpub.len(), 78);
    }

    #[tokio::test]
    async fn test_xpriv() {
        let path_indices = [84, 1, 0];
        let seed = &[0u8; 32];

        let mut xprv = bip32::XPrv::new(seed).unwrap();
        let mut xpub = bip32::XPub::from(&xprv);

        for &child_number in path_indices.iter() {
            xpub = xpub.derive_child(bip32::ChildNumber(child_number)).unwrap();
            xprv = xprv.derive_child(bip32::ChildNumber(child_number)).unwrap();
        }

        let mut bitcoin_xprv = Xpriv::new_master(Network::Bitcoin, seed).unwrap();
        let bitcoin_derivation_path: DerivationPath = "84/1/0".parse().unwrap();
        let secp = Secp256k1::new();
        bitcoin_xprv = bitcoin_xprv
            .derive_priv(&secp, &bitcoin_derivation_path)
            .unwrap();
        let bitcoin_xpub = Xpub::from_priv(&secp, &bitcoin_xprv);

        assert_eq!(xpub, bip32::XPub::from(&xprv));
        println!("Check successful!");

        println!("BIP32 XPrv: {}", xpub.to_string(bip32::Prefix::XPUB));
        println!(
            "BIP32 XPrv: {}",
            bip32::XPub::from(&xprv).to_string(bip32::Prefix::XPUB)
        );

        println!("BIP32 XPub: {}", bitcoin_xpub.to_string());
    }
}
