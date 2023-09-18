use kos_crypto::mnemonic::{generate_mnemonic as gm, validate_mnemonic as vm};

use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};

#[no_mangle]
pub extern "C" fn generate_mnemonic(count: *const c_uint) -> *mut c_char {
    let count = unsafe { *count };
    let u_count = usize::try_from(count).unwrap();
    let mnemonic = gm(u_count).unwrap().to_phrase();
    CString::new(mnemonic.to_owned()).unwrap().into_raw().into()
}

#[no_mangle]
pub extern "C" fn validate_mnemonic(phrase: *const c_char) -> bool {
    let c_str = unsafe { CStr::from_ptr(phrase) };
    let recipient = match c_str.to_str() {
        Err(_) => "",
        Ok(string) => string,
    };

    vm(recipient).is_ok()
}
