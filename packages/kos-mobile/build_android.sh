#!/bin/bash
source build_source.sh
set -o pipefail
set -e

if [ -n "$1" ]; then
  set_target_architecture "$1"
fi

if command -v nproc >/dev/null 2>&1; then
  CARGO_JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
  CARGO_JOBS=$(sysctl -n hw.ncpu)
else
  CARGO_JOBS=4
fi

configure_cargo() {
  cd "$BUILD_HOME"
  for i in $(seq 0 $((${#ANDROID_TOOLCHAINS[@]} - 1))); do
    toolchain="${ANDROID_TOOLCHAINS[i]}"
    if [ "$toolchain" = "armv7a-linux-androideabi" ]; then
      toolchain="armv7-linux-androideabi"
    fi
    rustup target add "$toolchain"
  done
  
  export AR="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/llvm-ar"
  export RANLIB="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/llvm-ranlib"
  export STRIP="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/llvm-strip"
  
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/aarch64-linux-android$ANDROID_MIN_API-clang"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/armv7a-linux-androideabi$ANDROID_MIN_API-clang"
  export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/i686-linux-android$ANDROID_MIN_API-clang"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/x86_64-linux-android$ANDROID_MIN_API-clang"
  
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$AR"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_AR="$AR"
  export CARGO_TARGET_I686_LINUX_ANDROID_AR="$AR"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$AR"
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
  export OPENSSL_INCLUDE_DIR="$OPENSSL_PATH/include"
  export OPENSSL_STATIC=1
  
  export CC="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/$toolchain$ANDROID_MIN_API-clang"
  export CXX="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/$toolchain$ANDROID_MIN_API-clang++"
  
  export PKG_CONFIG_ALLOW_CROSS=1
  export PKG_CONFIG_PATH=""
  export PKG_CONFIG_LIBDIR="$OPENSSL_LIB_DIR"
  
  log_status "assembling android lib to $toolchain..."
  log_status "Using OpenSSL from: $OPENSSL_LIB_DIR"
  
  if ! file_exists "$OPENSSL_LIB_DIR/libcrypto.a" || ! file_exists "$OPENSSL_LIB_DIR/libssl.a"; then
    log_error "OpenSSL libraries not found for $toolchain"
    return 1
  fi
  
  if ! cargo build --target "$rust_toolchain" --profile mobile -j "$CARGO_JOBS" -v; then
    log_error "Failed to build Rust library for $rust_toolchain"
    return 1
  fi
  
  local lib_path="../../target/$rust_toolchain/mobile/lib$PACKAGE_NAME.so"
  if ! validate_library_arch "$lib_path" "$jni"; then
    log_error "Built library validation failed for $rust_toolchain"
    return 1
  fi
  
  mkdir -p "$ANDROID_JNI_LIBS_PATH"
  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f "$lib_path" "$ANDROID_JNI_LIBS_PATH/$jni/"
  
  log_status "✓ Library copied to $ANDROID_JNI_LIBS_PATH/$jni/"
  
  unset CC CXX PKG_CONFIG_ALLOW_CROSS PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
  unset OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC
}

assemble_android_lib_unit_test() {
  cd "$BUILD_HOME"
  jni="$JNI_PLATFORM"
  log_status "assembling android test lib..."
  
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$OS_TOOLCHAIN"
  export OPENSSL_INCLUDE_DIR="$OPENSSL_PATH/include"
  export OPENSSL_STATIC=1
  
  if ! cargo build --profile mobile -j "$CARGO_JOBS" -v; then
    log_error "Failed to build unit test library"
    return 1
  fi
  
  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f "../../target/mobile/lib$PACKAGE_NAME.$LIB_EXTENSION" "$ANDROID_JNI_LIBS_PATH/$jni/"
  
  log_status "✓ Unit test library copied to $ANDROID_JNI_LIBS_PATH/$jni/"
  
  unset OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC
}

generate_binds() {
  cd "$BUILD_HOME"
  log_status "generating android binds..."

  # Use the target architecture for binding generation
  local binding_rust_toolchain="$BINDING_GENERATION_ARCH"
  if [ "$BINDING_GENERATION_ARCH" = "armv7a-linux-androideabi" ]; then
    binding_rust_toolchain="armv7-linux-androideabi"
  fi
  
  local binding_lib_path="../../target/$binding_rust_toolchain/mobile/lib$PACKAGE_NAME.so"
  
  if ! file_exists "$binding_lib_path"; then
    log_error "Library not found for binding generation: $binding_lib_path"
    log_error "Available libraries:"
    find ../../target -name "lib$PACKAGE_NAME.so" -type f 2>/dev/null || true
    return 1
  fi
  
  log_status "Generating bindings using library: $binding_lib_path"
  validate_library_arch "$binding_lib_path" "$BINDING_GENERATION_JNI"
  
  # Set up environment for binding generation to match the target library
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$BINDING_GENERATION_ARCH"
  export OPENSSL_INCLUDE_DIR="$OPENSSL_PATH/include"
  export OPENSSL_STATIC=1
  
  if ! cargo run -j "$CARGO_JOBS" -v --bin uniffi-bindgen generate --library "$binding_lib_path" --language kotlin --out-dir android_binds; then
    log_error "Failed to generate Kotlin bindings"
    return 1
  fi
  
  mkdir -p "$ANDROID_GENERATED_BINDS_PATH"
  cp -f -r android_binds/* "$ANDROID_GENERATED_BINDS_PATH"
  rm -rf android_binds
  
  log_status "✓ Kotlin bindings generated and copied"
  
  unset OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC
}

build_single_architecture() {
  local target_index=$TARGET_ARCH_INDEX
  log_status "Building single architecture: ${ANDROID_JNI[target_index]} (${ANDROID_TOOLCHAINS[target_index]})"
  
  assemble_openssl_lib "${ANDROID_ARCHS[target_index]}" "${ANDROID_TOOLCHAINS[target_index]}"
  assemble_android_lib "${ANDROID_TOOLCHAINS[target_index]}" "${ANDROID_JNI[target_index]}"
}

build_all_architectures() {
  log_status "Building all architectures..."
  for i in $(seq 0 $((${#ANDROID_ARCHS[@]} - 1))); do
    assemble_openssl_lib "${ANDROID_ARCHS[i]}" "${ANDROID_TOOLCHAINS[i]}"
    assemble_android_lib "${ANDROID_TOOLCHAINS[i]}" "${ANDROID_JNI[i]}"
  done
}

clear
echo -e "${ANDROID}########################################################${NC}"
echo -e "${ANDROID}#########  INITIALIZING ANDROID RUST BUILD  ############${NC}"
echo -e "${ANDROID}########################################################${NC}\n"

log_status "Target architecture: ${ANDROID_JNI[TARGET_ARCH_INDEX]} (${BINDING_GENERATION_ARCH})"

configure_android_ndk
configure_openssl
configure_cargo

if [ "$SINGLE_ARCH" = "true" ]; then
  log_status "Building single architecture for debugging..."
  build_single_architecture
else
  log_status "Building all architectures..."
  build_all_architectures
fi

# Always build host architecture for unit tests and bindings with proper OpenSSL
assemble_openssl_lib "$OS_ARCH" "$OS_TOOLCHAIN"
assemble_android_lib_unit_test
generate_binds

echo -e "${ANDROID}ANDROID RUST BUILD FINISHED${NC}"
echo "🎉🎉🎉"

echo -e "\n${ANDROID}Built libraries summary:${NC}"
if [ -d "$ANDROID_JNI_LIBS_PATH" ]; then
  find "$ANDROID_JNI_LIBS_PATH" -name "*.so" -o -name "*.dylib" | while read -r lib; do
    echo "  ✓ $lib"
    file "$lib" 2>/dev/null || true
  done
else
  log_warning "No libraries found in $ANDROID_JNI_LIBS_PATH"
fi