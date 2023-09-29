use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use kos_crypto::mnemonic::{ generate_mnemonic as gm, validate_mnemonic as vm };

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_kosrsintegration_NativeLibrary_generateMnemonic<'local>(
    env: JNIEnv<'local>,
    _: JClass,
    words: jint,
) -> JString<'local> {
    let count = words as i32;
    let u_count = usize::try_from(count).unwrap();
    let mnemonic = gm(u_count).unwrap().to_phrase();
    env.new_string(mnemonic).expect("error to get mnemonic")
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_kosrsintegration_NativeLibrary_validateMnemonic<'local>(
    mut env: JNIEnv<'local>,
    _: JClass<'local>,
    phrase: JString<'local>,
) -> bool {
    let mn: String = env.get_string(&phrase).unwrap().into();
    vm(mn.as_str()).is_ok()
}
