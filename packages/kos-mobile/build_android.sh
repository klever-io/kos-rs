#!/bin/bash

source build_source.sh

set -o pipefail
set -e

configure_cargo() {
  cd "$BUILD_HOME"
  for i in $(seq 0 $((${#ANDROID_TOOLCHAINS[@]} - 1))); do
    toolchain="${ANDROID_TOOLCHAINS[i]}"
    if [ "$toolchain" = "armv7a-linux-androideabi" ]; then
      toolchain="armv7-linux-androideabi"
    fi
    rustup target add $toolchain
  done
  export AR="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/llvm-ar"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/aarch64-linux-android$ANDROID_MIN_API-clang"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/armv7a-linux-androideabi$ANDROID_MIN_API-clang"
  export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/i686-linux-android$ANDROID_MIN_API-clang"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/x86_64-linux-android$ANDROID_MIN_API-clang"
}

assemble_android_lib() {
  toolchain=$1
  jni=$2
  rust_toolchain=$toolchain
  cd "$BUILD_HOME"
  if [ "$toolchain" = "armv7a-linux-androideabi" ]; then
    rust_toolchain="armv7-linux-androideabi"
  fi
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$toolchain"
  export CC="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/$toolchain$ANDROID_MIN_API-clang"
  log_status "assembling android lib to $toolchain..."
  cargo build --target $rust_toolchain --release -q
  export CC=""
  mkdir -p "$ANDROID_JNI_LIBS_PATH"
  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f ../../target/$rust_toolchain/release/lib"$PACKAGE_NAME".so "$ANDROID_JNI_LIBS_PATH"/"$jni"
}

assemble_android_lib_unit_test() {
  cd "$BUILD_HOME"
  jni="$JNI_PLATFORM"
  log_status "assembling android test lib..."
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$OS_TOOLCHAIN"
  cargo build --release -q
  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f ../../target/release/lib"$PACKAGE_NAME"."$LIB_EXTENSION" "$ANDROID_JNI_LIBS_PATH"/$jni
}

generate_binds() {
  cd "$BUILD_HOME"
  log_status "generating android binds..."
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$OS_TOOLCHAIN"
  cargo run -q --bin uniffi-bindgen generate --library ../../target/"${ANDROID_TOOLCHAINS[0]}"/release/lib"${PACKAGE_NAME}".so --language kotlin --out-dir android_binds
  mkdir -p "$ANDROID_GENERATED_BINDS_PATH"
  cp -f -r android_binds/* "$ANDROID_GENERATED_BINDS_PATH"
  rm -rf android_binds
}

clear
echo -e "${ANDROID}########################################################${NC}"
echo -e "${ANDROID}#########  INITIALIZING ANDROID RUST BUILD  ############${NC}"
echo -e "${ANDROID}########################################################${NC}\n"

configure_android_ndk
configure_openssl
configure_cargo

for i in $(seq 0 $((${#ANDROID_ARCHS[@]} - 1))); do
  assemble_openssl_lib "${ANDROID_ARCHS[i]}" "${ANDROID_TOOLCHAINS[i]}"
  assemble_android_lib "${ANDROID_TOOLCHAINS[i]}" "${ANDROID_JNI[i]}"
done

assemble_openssl_lib "$OS_ARCH" "$OS_TOOLCHAIN"
assemble_android_lib_unit_test
generate_binds

echo -e "${ANDROID}ANDROID RUST BUILD FINISHED 🎉🎉🎉${NC}"
