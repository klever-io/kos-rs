use crate::crypto::ed25519::{Ed25519Err, Ed25519Trait};
use crate::crypto::ed25519_bip32::{add28_mul8, add_mod256};
use crate::crypto::pbkdf2::{Pbkdf2, Pbkdf2Trait};
use crate::crypto::secp256k1::{Secp256Err, Secp256K1, Secp256k1Trait};
use crate::crypto::sr25519::{Sr25519, Sr25519Error, Sr25519Trait};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use bip39_dict::{Entropy, ENGLISH};
use core::fmt::{Display, Formatter};
use core::num::ParseIntError;
use core::str::FromStr;
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

const BTC_SEED_NAME: &[u8] = b"Bitcoin seed";
const ED25519_NAME: &[u8] = b"ed25519 seed";

const BIP39_PBKDF2_ROUNDS: u32 = 2048;

#[derive(Debug)]
pub enum Bip32Err {
    ConversionErr,
    Secp256Err(Secp256Err),
    Sr25519Error(Sr25519Error),
    HmacError,
    DeriveError,
    PathError,
    InvalidMnemonic,
}

impl Display for Bip32Err {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Bip32Err::ConversionErr => write!(f, "Conversion error"),
            Bip32Err::Secp256Err(v) => write!(f, "Curve error: {}", v),
            Bip32Err::PathError => write!(f, "Path error"),
            Bip32Err::DeriveError => write!(f, "Derive error"),
            Bip32Err::InvalidMnemonic => write!(f, "Invalid mnemonic"),
            Bip32Err::Sr25519Error(v) => write!(f, "Sr25519 error: {}", v),
            Bip32Err::HmacError => write!(f, "Hmac error"),
        }
    }
}

impl From<ParseIntError> for Bip32Err {
    fn from(_: ParseIntError) -> Self {
        Bip32Err::ConversionErr
    }
}

impl From<Secp256Err> for Bip32Err {
    fn from(value: Secp256Err) -> Self {
        Bip32Err::Secp256Err(value)
    }
}

impl From<Ed25519Err> for Bip32Err {
    fn from(_: Ed25519Err) -> Self {
        Bip32Err::DeriveError
    }
}

impl From<Sr25519Error> for Bip32Err {
    fn from(value: Sr25519Error) -> Self {
        Bip32Err::Sr25519Error(value)
    }
}

impl From<InvalidLength> for Bip32Err {
    fn from(_: InvalidLength) -> Self {
        Bip32Err::HmacError
    }
}

type Hmac512 = Hmac<sha2::Sha512>;
pub fn compute_hmac(message: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Bip32Err> {
    let mut mac = Hmac512::new_from_slice(key)?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let vec_result = result.to_vec();
    let mut left = vec![0u8; 32];
    let mut right = vec![0u8; 32];
    left.copy_from_slice(&vec_result[..32]);
    right.copy_from_slice(&vec_result[32..]);

    Ok((left, right))
}

pub fn compute_master_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Bip32Err> {
    let (left, right) = compute_hmac(seed, BTC_SEED_NAME)?;
    Ok((left, right))
}

pub struct PathComponent {
    pub is_hardened: bool,
    pub index: u32,
}

pub fn handle_path(path: String) -> Result<Vec<PathComponent>, Bip32Err> {
    let mut components: Vec<&str> = path.split('/').collect();
    Vec::remove(&mut components, 0);
    let mut path_components: Vec<PathComponent> = Vec::new();

    for component in components {
        let mut is_hardened = false;
        let index: u32;
        if component.contains("'") {
            is_hardened = true;
            index = component.replace("'", "").parse::<u32>().unwrap();
        } else {
            index = component.parse::<u32>()?
        }

        path_components.push(PathComponent { is_hardened, index });
    }

    return Ok(path_components);
}

pub fn derive_private_key(
    pvk: &[u8; 32],
    ch: &[u8; 32],
    mut pc: PathComponent,
) -> Result<([u8; 32], [u8; 32]), Bip32Err> {
    let mut data: Vec<u8> = Vec::new();
    if pc.is_hardened {
        pc.index |= 0x80000000;
        data.push(0);
        data.extend_from_slice(pvk);
    } else {
        let pbk = Secp256K1::private_to_public_compressed(pvk)?;
        data = Vec::from(pbk);
    }

    data.extend_from_slice(&pc.index.to_be_bytes());
    let (hmac_master, hmac_ch) = compute_hmac(&data, ch)?;
    let mut new_data: [u8; 32] = [0; 32];
    let mut new_ch: [u8; 32] = [0; 32];
    new_data.copy_from_slice(&hmac_master[..32]);
    new_ch.copy_from_slice(&hmac_ch[..32]);

    let x = Secp256K1::add_scalars(pvk, &new_data)?;

    return Ok((x, new_ch));
}

pub fn derive_pk_from_path(
    pvk: &[u8],
    ch: &[u8],
    path_c: Vec<PathComponent>,
) -> Result<[u8; 32], Bip32Err> {
    let mut data: [u8; 32] = [0; 32];
    data.copy_from_slice(pvk);

    let mut chaincode: [u8; 32] = [0; 32];
    chaincode.copy_from_slice(ch);

    for component in path_c {
        let (new_data, new_ch) = derive_private_key(&data, &chaincode, component)?;
        data.copy_from_slice(&new_data);
        chaincode.copy_from_slice(&new_ch);
    }

    Ok(data)
}
pub fn derive(input_key: &[u8], path: String) -> Result<[u8; 32], Bip32Err> {
    let path_components = handle_path(path)?;
    let (master_key, chain_code) = compute_master_from_seed(input_key)?;
    let pk = derive_pk_from_path(&master_key, &chain_code, path_components)?;
    Ok(pk)
}

pub fn derive_ed25519(input_key: &[u8], path: String) -> Result<[u8; 32], Bip32Err> {
    let path_components = handle_path(path)?;

    let (mut key, mut chaincode) = compute_hmac(input_key, ED25519_NAME)?;

    for mut component in path_components {
        let mut data = Vec::new();
        data.push(0);
        data.extend_from_slice(&key[..32]);
        if component.is_hardened {
            component.index |= 0x80000000;
        }

        data.extend_from_slice(&component.index.to_be_bytes());
        let (hmac_master, hmac_ch) = compute_hmac(&data, &chaincode)?;
        key = hmac_master;
        chaincode = hmac_ch;
    }

    let mut result_key: [u8; 32] = [0; 32];
    result_key.copy_from_slice(&key[..32]);
    Ok(result_key)
}

pub fn derive_sr25519(input_key: &[u8], mut path: String) -> Result<[u8; 64], Bip32Err> {
    let mut chaincode = [0u8; 32];
    let mut is_hardned = false;
    if path != "" {
        path = path
            .strip_prefix("//")
            .ok_or(Bip32Err::PathError)?
            .to_string();
        path = path
            .strip_suffix("///")
            .ok_or(Bip32Err::PathError)?
            .to_string();

        let chaincode_value = u8::from_str(path.as_str()).map_err(|_| Bip32Err::PathError)?;

        chaincode[0] = chaincode_value;
        is_hardned = true;
    }

    let mut mini_sk = [0; 32];
    mini_sk.copy_from_slice(&input_key[..32]);

    let (mut sk, mut nonce) = Sr25519::expand_secret_key(&mini_sk)?;
    if is_hardned {
        let mini_sk = Sr25519::hard_derive_mini_sk(&mini_sk, &chaincode)?;
        (sk, nonce) = Sr25519::expand_secret_key(&mini_sk)?
    }

    let mut result_key: [u8; 64] = [0; 64];
    result_key[..32].copy_from_slice(&sk);
    result_key[32..].copy_from_slice(&nonce);

    Ok(result_key)
}

pub fn mnemonic_to_seed(mnemonic: String, password: String) -> Result<Vec<u8>, Bip32Err> {
    let mut salt = String::from("mnemonic");
    salt.push_str(password.as_str());
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        BIP39_PBKDF2_ROUNDS,
        &mut seed,
    );
    Ok(Vec::from(seed))
}

pub fn mnemonic_to_seed_substrate(mnemonic: String, password: String) -> Result<Vec<u8>, Bip32Err> {
    let entropy = mnemonic_to_entropy(mnemonic)?;
    let mut salt = String::from("mnemonic");
    salt.push_str(password.as_str());
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(
        entropy.as_slice(),
        salt.as_bytes(),
        BIP39_PBKDF2_ROUNDS,
        &mut seed,
    );
    Ok(Vec::from(seed))
}

pub fn mnemonic_to_entropy(mnemonic: String) -> Result<Vec<u8>, Bip32Err> {
    let words_count = mnemonic.split(" ").count();
    match words_count {
        12 => mnemonic_to_entropy_12(mnemonic),
        24 => mnemonic_to_entropy_24(mnemonic),
        _ => Err(Bip32Err::InvalidMnemonic),
    }
}

pub fn mnemonic_to_entropy_12(mnemonic: String) -> Result<Vec<u8>, Bip32Err> {
    let mnemonic =
        bip39_dict::Mnemonics::<12>::from_string(&bip39_dict::ENGLISH, mnemonic.as_str())
            .map_err(|_| Bip32Err::InvalidMnemonic)?;

    let entropy =
        Entropy::<16>::from_mnemonics::<12, 4>(&mnemonic).map_err(|_| Bip32Err::InvalidMnemonic)?;

    Ok(entropy.0.to_vec())
}

pub fn mnemonic_to_entropy_24(mnemonic: String) -> Result<Vec<u8>, Bip32Err> {
    let mnemonic =
        bip39_dict::Mnemonics::<24>::from_string(&bip39_dict::ENGLISH, mnemonic.as_str())
            .map_err(|_| Bip32Err::InvalidMnemonic)?;

    let entropy =
        Entropy::<32>::from_mnemonics::<24, 8>(&mnemonic).map_err(|_| Bip32Err::InvalidMnemonic)?;

    Ok(entropy.0.to_vec())
}

pub fn mnemonic_to_seed_ed25519_bip32(mnemonic: String) -> Result<Vec<u8>, Bip32Err> {
    let entropy = mnemonic_to_entropy(mnemonic)?;
    let icarus_key = Pbkdf2::pbkdf2_hmac_512::<96>(&[], &entropy, 4096);

    let mut pvk = icarus_key.to_vec();
    pvk[0] &= 0xf8;
    pvk[31] &= 0x1f;
    pvk[31] |= 0x40;

    return Ok(pvk);
}

pub fn derive_ed25519_bip32(input_key: [u8; 96], path: String) -> Result<[u8; 96], Bip32Err> {
    let path_components = handle_path(path)?;
    let mut pvk = [0u8; 64];
    let mut chaincode = [0u8; 32];

    pvk.copy_from_slice(&input_key[..64]);
    chaincode.copy_from_slice(&input_key[64..]);

    for mut component in path_components {
        if component.is_hardened {
            component.index |= 0x80000000;
        }

        let mut zmac = Hmac512::new_from_slice(&chaincode)?;
        let mut ccmac = Hmac512::new_from_slice(&chaincode)?;

        let sindex = component.index.to_le_bytes().to_vec();

        if component.is_hardened {
            zmac.update(&[0]);
            zmac.update(&pvk);
            zmac.update(&sindex);
            ccmac.update(&[0x01]);
            ccmac.update(&pvk);
            ccmac.update(&sindex);
        } else {
            let pub_key = crate::crypto::ed25519::Ed25519::public_from_extended(&pvk)?;
            zmac.update(&[0x02]);
            zmac.update(&pub_key);
            zmac.update(&sindex);
            ccmac.update(&[0x03]);
            ccmac.update(&pub_key);
            ccmac.update(&sindex);
        }

        let z = zmac.finalize().into_bytes();
        let zl = z[..32].to_vec();
        let zr = z[32..].to_vec();

        let kl = add28_mul8(&pvk[0..32], &zl);
        let kr = add_mod256(&pvk[32..64], &zr);

        let cc = ccmac.finalize().into_bytes();
        let cc = cc[32..].to_vec();

        pvk[0..32].copy_from_slice(&kl);
        pvk[32..64].copy_from_slice(&kr);
        chaincode.copy_from_slice(&cc);
    }

    let mut result_key: [u8; 96] = [0; 96];
    result_key[..64].copy_from_slice(&pvk);
    result_key[64..].copy_from_slice(&chaincode);

    Ok(result_key)
}
