#[allow(unused_imports)]
use rand_core::{CryptoRng, Error, RngCore};

#[cfg(feature = "ksafe")]
extern "C" {
    #[allow(dead_code)]
    fn random_buffer(p_buffer: *mut u8, size: u32);
}

#[cfg(feature = "ksafe")]
#[allow(dead_code)]
struct MyRng;

#[cfg(feature = "ksafe")]
impl RngCore for MyRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        unsafe {
            random_buffer(buf.as_mut_ptr(), buf.len() as u32);
        }
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        unsafe {
            random_buffer(buf.as_mut_ptr(), buf.len() as u32);
        }
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            random_buffer(dest.as_mut_ptr(), dest.len() as u32);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "ksafe")]
impl CryptoRng for MyRng {}

#[cfg(not(feature = "ksafe"))]
pub fn getrandom_or_panic() -> impl RngCore + CryptoRng {
    rand_core::OsRng
}

#[cfg(feature = "ksafe")]
pub fn getrandom_or_panic() -> impl RngCore + CryptoRng {
    MyRng
}
