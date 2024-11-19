pub mod b58;
pub mod base64;
pub mod bignum;
pub mod bip32;
pub mod ed25519;
mod ed25519_bip32;
pub mod hash;
mod pbkdf2;
mod rng;
pub mod secp256k1;
pub mod sr25519;

#[cfg(not(feature = "ksafe"))]
pub mod mnemonic;

mod crypto {}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use alloc::string::String;

    #[test]
    fn test_path() {
        let path = String::from("m/44'/0'/0'/0/0");
        let path_components = crypto::bip32::handle_path(path).unwrap();
        assert_eq!(path_components.len(), 5);
    }

    #[test]
    fn test_derive() {
        let seed = hex::decode(
            "5eb00bbddc\
        f069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19\
        a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2\
        ce9e38e4",
        )
        .unwrap();
        let path = String::from("m/44'/195'/0'/0/0");
        let pvk = crypto::bip32::derive(&seed, path).unwrap();
        assert_eq!(pvk.len(), 32);
    }
}
