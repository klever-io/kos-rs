#[cfg(feature = "ksafe")]
extern "C" {
    fn c_pbkdf2_hmac_sha512(
        pass: *const u8,
        pass_len: u32,
        salt: *const u8,
        salt_len: u32,
        rounds: u32,
        out: *mut u8,
        out_len: u32,
    );
}

pub trait Pbkdf2Trait {
    fn pbkdf2_hmac_512<const N: usize>(password: &[u8], salt: &[u8], rounds: u32) -> [u8; N];
}

pub struct Pbkdf2 {}

#[cfg(not(feature = "ksafe"))]
impl Pbkdf2Trait for Pbkdf2 {
    fn pbkdf2_hmac_512<const N: usize>(password: &[u8], salt: &[u8], rounds: u32) -> [u8; N] {
        pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, N>(password, salt, rounds)
    }
}

#[cfg(feature = "ksafe")]
impl Pbkdf2Trait for Pbkdf2 {
    fn pbkdf2_hmac_512<const N: usize>(password: &[u8], salt: &[u8], rounds: u32) -> [u8; N] {
        let mut out = [0u8; N];
        unsafe {
            c_pbkdf2_hmac_sha512(
                password.as_ptr(),
                password.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                rounds,
                out.as_mut_ptr(),
                N as u32,
            );
        }
        out
    }
}
