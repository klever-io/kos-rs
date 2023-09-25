use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use kos_crypto::mnemonic::generate_mnemonic as gm;

// use std::convert::TryFrom;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_kosrsintegration_NativeLibrary_generateMnemonic<
    'local,
>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
) -> JString<'local> {
    let mnemonic = gm(24).unwrap().to_phrase();
    env.new_string(mnemonic).expect("error to get mnemonic")
}
