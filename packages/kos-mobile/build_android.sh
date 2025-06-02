#!/bin/bash

source build_source.sh

set -o pipefail
set -e

# USE_CACHE=true make build-android inm root folder to use cache
USE_CACHE=${USE_CACHE:-false}
CACHE_DIR="${BUILD_HOME}/.build_cache"

init_cache() {
  if [ "$USE_CACHE" = "true" ]; then
    mkdir -p "$CACHE_DIR"/{checksums,cargo_target,openssl_libs,binds}
    log_status "Cache directory initialized at $CACHE_DIR"
  fi
}

if command -v nproc >/dev/null 2>&1; then
  CARGO_JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
  CARGO_JOBS=$(sysctl -n hw.ncpu)
else
  CARGO_JOBS=4
fi

generate_source_checksum() {
  local checksum_file="$CACHE_DIR/checksums/source.sha256"
  
  mkdir -p "$CACHE_DIR/checksums"

  find "$BUILD_HOME" -name "Cargo.toml" -o -name "Cargo.lock" -o -name "*.rs" |
    sort | xargs cat | sha256sum >"$checksum_file.tmp"

  cat "$0" build_source.sh >>"$checksum_file.tmp" 2>/dev/null || true

  sha256sum "$checksum_file.tmp" | cut -d' ' -f1 >"$checksum_file"
  rm "$checksum_file.tmp"

  cat "$checksum_file"
}

openssl_cache_valid() {
  if [ "$USE_CACHE" != "true" ]; then
    return 1
  fi

  local toolchain=$1
  local cache_marker="$CACHE_DIR/checksums/openssl_${toolchain}.marker"

  [ -f "$cache_marker" ] &&
    [ -d "$CACHE_DIR/openssl_libs/$toolchain" ] &&
    [ -d "$OPENSSL_GENERATED_LIBS_PATH/$toolchain" ]
}

cache_openssl_libs() {
  if [ "$USE_CACHE" != "true" ]; then
    return
  fi

  local toolchain=$1
  log_status "Caching OpenSSL libraries for $toolchain..."

  mkdir -p "$CACHE_DIR/openssl_libs/$toolchain"
  if [ -d "$OPENSSL_GENERATED_LIBS_PATH/$toolchain" ]; then
    cp -r "$OPENSSL_GENERATED_LIBS_PATH/$toolchain"/* "$CACHE_DIR/openssl_libs/$toolchain/"
    touch "$CACHE_DIR/checksums/openssl_${toolchain}.marker"
  fi
}

restore_openssl_cache() {
  local toolchain=$1
  log_status "Restoring OpenSSL libraries from cache for $toolchain..."

  mkdir -p "$OPENSSL_GENERATED_LIBS_PATH/$toolchain"
  cp -r "$CACHE_DIR/openssl_libs/$toolchain"/* "$OPENSSL_GENERATED_LIBS_PATH/$toolchain/"
}

cargo_cache_valid() {
  if [ "$USE_CACHE" != "true" ]; then
    return 1
  fi

  local target=$1
  local cache_marker="$CACHE_DIR/checksums/cargo_${target}.marker"
  local current_checksum
  current_checksum=$(generate_source_checksum)

  if [ ! -f "$cache_marker" ]; then
    return 1
  fi

  local cached_checksum
  cached_checksum=$(cat "$cache_marker")
  [ "$current_checksum" = "$cached_checksum" ] &&
    [ -f "../../target/$target/mobile/lib${PACKAGE_NAME}.so" ]
}

cache_cargo_build() {
  if [ "$USE_CACHE" != "true" ]; then
    return
  fi

  local target=$1
  local current_checksum
  current_checksum=$(generate_source_checksum)

  echo "$current_checksum" >"$CACHE_DIR/checksums/cargo_${target}.marker"
  log_status "Cached Cargo build for target $target"
}

assemble_openssl_lib_cached() {
  local arch=$1
  local toolchain=$2

  if openssl_cache_valid "$toolchain"; then
    log_status "Using cached OpenSSL libraries for $toolchain"
    restore_openssl_cache "$toolchain"
  else
    log_status "Building OpenSSL for $toolchain..."
    assemble_openssl_lib "$arch" "$toolchain"
    cache_openssl_libs "$toolchain"
  fi
}

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

  if cargo_cache_valid "$rust_toolchain"; then
    log_status "Using cached build for $rust_toolchain"
  else
    export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$toolchain"
    export CC="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS/bin/$toolchain$ANDROID_MIN_API-clang"
    log_status "assembling android lib to $toolchain..."
    cargo build --target "$rust_toolchain" --profile mobile -j "$CARGO_JOBS" -q
    export CC=""
    cache_cargo_build "$rust_toolchain"
  fi

  mkdir -p "$ANDROID_JNI_LIBS_PATH"
  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f ../../target/"$rust_toolchain"/mobile/lib"$PACKAGE_NAME".so "$ANDROID_JNI_LIBS_PATH"/"$jni"
}

assemble_android_lib_unit_test() {
  cd "$BUILD_HOME"
  jni="$JNI_PLATFORM"

  if cargo_cache_valid "debug"; then
    log_status "Using cached test build"
  else
    log_status "assembling android test lib..."
    export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$OS_TOOLCHAIN"
    cargo build --profile mobile -j "$CARGO_JOBS" -q
    cache_cargo_build "debug"
  fi

  mkdir -p "$ANDROID_JNI_LIBS_PATH/$jni"
  cp -f ../../target/mobile/lib"$PACKAGE_NAME"."$LIB_EXTENSION" "$ANDROID_JNI_LIBS_PATH"/"$jni"
}

generate_binds() {
  cd "$BUILD_HOME"
  local binds_cache_marker="$CACHE_DIR/checksums/binds.marker"
  local current_checksum
  current_checksum=$(generate_source_checksum)

  if [ "$USE_CACHE" = "true" ] && [ -f "$binds_cache_marker" ]; then
    local cached_checksum
    cached_checksum=$(cat "$binds_cache_marker")
    if [ "$current_checksum" = "$cached_checksum" ] && [ -d "$CACHE_DIR/binds" ]; then
      log_status "Using cached bindings"
      mkdir -p "$ANDROID_GENERATED_BINDS_PATH"
      cp -f -r "$CACHE_DIR/binds"/* "$ANDROID_GENERATED_BINDS_PATH"
      return
    fi
  fi

  log_status "generating android binds..."
  export OPENSSL_LIB_DIR="$OPENSSL_GENERATED_LIBS_PATH/$OS_TOOLCHAIN"
  cargo run -j "$CARGO_JOBS" -q --bin uniffi-bindgen generate --library ../../target/"${ANDROID_TOOLCHAINS[0]}"/mobile/lib"${PACKAGE_NAME}".so --language kotlin --out-dir android_binds

  mkdir -p "$ANDROID_GENERATED_BINDS_PATH"
  cp -f -r android_binds/* "$ANDROID_GENERATED_BINDS_PATH"

  if [ "$USE_CACHE" = "true" ]; then
    mkdir -p "$CACHE_DIR/binds"
    cp -f -r android_binds/* "$CACHE_DIR/binds"
    echo "$current_checksum" >"$binds_cache_marker"
  fi

  rm -rf android_binds
}

clear
echo -e "${ANDROID}########################################################${NC}"
echo -e "${ANDROID}#########  INITIALIZING ANDROID RUST BUILD  ############${NC}"
echo -e "${ANDROID}########################################################${NC}\n"

if [ "$USE_CACHE" = "true" ]; then
  log_status "Caching enabled"
  init_cache
else
  log_status "Caching disabled"
fi

if ! declare -F configure_android_ndk >/dev/null; then
  log_status "Warning: configure_android_ndk function not found, using basic NDK configuration"
  configure_android_ndk() {
    if [ -z "$ANDROID_NDK_PATH" ]; then
      log_status "Error: ANDROID_NDK_PATH not set"
      exit 1
    fi

    if [ ! -d "$ANDROID_NDK_PATH" ]; then
      log_status "Error: Android NDK not found at $ANDROID_NDK_PATH"
      exit 1
    fi

    log_status "Android NDK configured at: $ANDROID_NDK_PATH"
  }
fi

configure_android_ndk
configure_openssl
configure_cargo

for i in $(seq 0 $((${#ANDROID_ARCHS[@]} - 1))); do
  assemble_openssl_lib_cached "${ANDROID_ARCHS[i]}" "${ANDROID_TOOLCHAINS[i]}"
  assemble_android_lib "${ANDROID_TOOLCHAINS[i]}" "${ANDROID_JNI[i]}"
done

assemble_openssl_lib_cached "$OS_ARCH" "$OS_TOOLCHAIN"
assemble_android_lib_unit_test
generate_binds

echo -e "${ANDROID}ANDROID RUST BUILD FINISHED${NC}"
echo "🎉🎉🎉"