use core::fmt::{Display, Formatter};

#[derive(Debug)]
#[allow(dead_code)]
pub enum Secp256Err {
    ErrDerive,
}

impl Display for Secp256Err {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Secp256Err::ErrDerive => write!(f, "Derive error"),
        }
    }
}

#[cfg(not(feature = "ksafe"))]
impl From<libsecp256k1::Error> for Secp256Err {
    fn from(_: libsecp256k1::Error) -> Self {
        Secp256Err::ErrDerive
    }
}

pub struct Secp256K1 {}

#[cfg(feature = "ksafe")]
extern "C" {
    fn c_ecdsa_secp256k1_sign(msg: *const u8, msg_len: u32, pvk: *const u8, sig: *mut u8);

    fn c_ecdsa_scalar_add(a: *const u8, b: *const u8, c: *mut u8) -> u8; // Assuming that C's `bool` is equivalent to Rust's `u8` here

    fn c_ecdsa_get_pub_key65(pvk: *const u8, pbk: *mut u8);

    fn c_ecdsa_get_pub_key33(pvk: *const u8, pbk: *mut u8);
}

pub trait Secp256k1Trait {
    fn add_scalars(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Secp256Err>;
    fn private_to_public_compressed(pvk: &[u8; 32]) -> Result<[u8; 33], Secp256Err>;
    fn private_to_public_uncompressed(pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err>;
    fn sign(msg: &[u8; 32], pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err>;
}

#[cfg(feature = "ksafe")]
impl Secp256k1Trait for Secp256K1 {
    fn add_scalars(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Secp256Err> {
        let mut c = [0; 32];
        unsafe {
            c_ecdsa_scalar_add(a.as_ptr(), b.as_ptr(), c.as_mut_ptr());
        }

        Ok(c)
    }

    fn private_to_public_compressed(pvk: &[u8; 32]) -> Result<[u8; 33], Secp256Err> {
        let mut pbk = [0; 33];
        unsafe {
            c_ecdsa_get_pub_key33(pvk.as_ptr(), pbk.as_mut_ptr());
        }

        Ok(pbk)
    }

    fn private_to_public_uncompressed(pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err> {
        let mut pbk = [0; 65];
        unsafe {
            c_ecdsa_get_pub_key65(pvk.as_ptr(), pbk.as_mut_ptr());
        }

        Ok(pbk)
    }

    fn sign(msg: &[u8; 32], pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err> {
        let mut sig = [0; 65];
        unsafe {
            c_ecdsa_secp256k1_sign(
                msg.as_ptr(),
                msg.len() as u32,
                pvk.as_ptr(),
                sig.as_mut_ptr(),
            );
        }

        Ok(sig)
    }
}

#[cfg(not(feature = "ksafe"))]
impl Secp256k1Trait for Secp256K1 {
    fn add_scalars(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Secp256Err> {
        let mut a = libsecp256k1::SecretKey::parse(a)?;
        let b = libsecp256k1::SecretKey::parse(b)?;
        a.tweak_add_assign(&b)?;
        Ok(a.serialize())
    }

    fn private_to_public_compressed(pvk: &[u8; 32]) -> Result<[u8; 33], Secp256Err> {
        let sk = libsecp256k1::SecretKey::parse(pvk)?;
        let pbk = libsecp256k1::PublicKey::from_secret_key(&sk);
        Ok(pbk.serialize_compressed())
    }

    fn private_to_public_uncompressed(pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err> {
        let sk = libsecp256k1::SecretKey::parse(pvk)?;
        let pbk = libsecp256k1::PublicKey::from_secret_key(&sk);
        Ok(pbk.serialize())
    }

    fn sign(msg: &[u8; 32], pvk: &[u8; 32]) -> Result<[u8; 65], Secp256Err> {
        let sk = libsecp256k1::SecretKey::parse(pvk)?;
        let msg = libsecp256k1::Message::parse(msg);
        let (sig, rec) = libsecp256k1::sign(&msg, &sk);

        let mut sig_vec: [u8; 65] = [0; 65];
        sig_vec[..64].copy_from_slice(&sig.serialize()[..]);
        sig_vec[64] = rec.serialize();
        Ok(sig_vec)
    }
}
