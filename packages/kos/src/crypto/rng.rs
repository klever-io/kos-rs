use core::convert::Infallible;
use rand_core::{CryptoRng, Rng, TryCryptoRng, TryRng};

#[cfg(feature = "ksafe")]
extern "C" {
    #[allow(dead_code)]
    fn random_buffer(p_buffer: *mut u8, size: u32);
}

#[cfg(feature = "ksafe")]
#[allow(dead_code)]
struct MyRng;

#[cfg(feature = "ksafe")]
impl TryRng for MyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        unsafe {
            random_buffer(buf.as_mut_ptr(), buf.len() as u32);
        }
        Ok(u32::from_ne_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        unsafe {
            random_buffer(buf.as_mut_ptr(), buf.len() as u32);
        }
        Ok(u64::from_ne_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        unsafe {
            random_buffer(dest.as_mut_ptr(), dest.len() as u32);
        }
        Ok(())
    }
}

#[cfg(feature = "ksafe")]
impl TryCryptoRng for MyRng {}

#[cfg(not(feature = "ksafe"))]
pub fn getrandom_or_panic() -> impl Rng + CryptoRng {
    rand_core::OsRng
}

#[cfg(feature = "ksafe")]
pub fn getrandom_or_panic() -> impl Rng + CryptoRng {
    MyRng
}
