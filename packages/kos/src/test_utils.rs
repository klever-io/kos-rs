use alloc::string::{String, ToString};

/// Gets the test mnemonic from environment variable KOS_MNEMONIC_FOR_TEST
/// If the environment variable is not set, returns the default test mnemonic
pub fn get_test_mnemonic() -> String {
    // For now, we'll always return the default mnemonic since we can't use std::env in no_std
    // In the future, this could be enhanced with a custom environment variable mechanism
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .to_string()
}
