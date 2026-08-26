#[cfg(not(feature = "ksafe"))]
pub fn getrandom_or_panic() -> impl rand_core_0_6::RngCore + rand_core_0_6::CryptoRng {
    rand_core_0_6::OsRng
}

#[cfg(all(feature = "ksafe", not(test)))]
extern "C" {
    fn random_buffer(p_buffer: *mut u8, size: u32);
}

#[cfg(all(feature = "ksafe", test))]
#[no_mangle]
unsafe extern "C" fn random_buffer(p_buffer: *mut u8, size: u32) {
    let slice = core::slice::from_raw_parts_mut(p_buffer, size as usize);
    for (i, byte) in slice.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(42);
    }
}

#[cfg(feature = "ksafe")]
pub struct MyRng;

#[cfg(feature = "ksafe")]
impl rand_core_0_6::RngCore for MyRng {
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

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_0_6::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "ksafe")]
impl rand_core_0_6::CryptoRng for MyRng {}

#[cfg(feature = "ksafe")]
impl rand_core::TryRng for MyRng {
    type Error = core::convert::Infallible;

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
impl rand_core::TryCryptoRng for MyRng {}

#[cfg(feature = "ksafe")]
pub fn getrandom_or_panic() -> impl rand_core_0_6::RngCore + rand_core_0_6::CryptoRng {
    MyRng
}
