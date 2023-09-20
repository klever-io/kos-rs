use kos_crypto::mnemonic::generate_mnemonic as gm;
use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;

use std::convert::TryFrom;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_kosrsintegration_NativeLibrary_generateMnemonic<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
    count: jint,
) -> JString<'local> {
    let u_count = usize::try_from(count).unwrap();
    let mnemonic = gm(u_count).unwrap().to_phrase();
    env.new_string(mnemonic).expect("error to get mnemonic")
}
