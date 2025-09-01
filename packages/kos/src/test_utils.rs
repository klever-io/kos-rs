use alloc::string::String;

pub fn get_test_mnemonic() -> String {
    String::from(env!("KOS_MNEMONIC_FOR_TEST"))
}
