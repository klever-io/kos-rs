use rand_core::{CryptoRng, RngCore};

#[cfg(not(target_arch = "x86_64"))]
extern "C" {
    #[allow(dead_code)]
    fn random_buffer(p_buffer: *mut u8, size: u32);
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
struct MyRng;

#[cfg(not(target_arch = "x86_64"))]
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

#[cfg(not(target_arch = "x86_64"))]
impl CryptoRng for MyRng {}

#[cfg(target_arch = "x86_64")]
pub fn getrandom_or_panic() -> impl RngCore + CryptoRng {
    rand_core::OsRng
}

#[cfg(not(target_arch = "x86_64"))]
pub fn getrandom_or_panic() -> impl RngCore + CryptoRng {
    MyRng
}
