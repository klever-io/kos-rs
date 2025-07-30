use alloc::string::{String, ToString};

#[cfg(feature = "std")]
pub fn get_test_mnemonic() -> alloc::string::String {
    std::env::var("KOS_MNEMONIC_FOR_TEST").expect("KOS_MNEMONIC_FOR_TEST must be set");
}
