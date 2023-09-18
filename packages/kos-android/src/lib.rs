use kos_crypto::mnemonic::{generate_mnemonic as gm, validate_mnemonic as vm};
use jni::objects::{JClass, JString};
// use jni::sys::jstring;
use jni::JNIEnv;

use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_kosrsintegration_NativeLibrary_generate_mnemonic<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
    count: jni::sys::jint<'local>,
) -> JString<'local> {
    let u_count = usize::try_from(count).unwrap();
    let mnemonic = gm(u_count).unwrap().to_phrase();
    env.new_string(mnemonic).expect("error to get mnemonic")
}
