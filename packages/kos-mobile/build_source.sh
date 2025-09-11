#!/bin/bash

# build env
BUILD_HOME=$(pwd)

if [[ "$OSTYPE" == "darwin"* ]]; then
  export OS="darwin-x86_64"
  export OS_ARCH="darwin64-arm64-cc"
  export OS_TOOLCHAIN="darwin-x86_64"
  export IS_MACOS=true
  export LIB_EXTENSION="dylib"
  export JNI_PLATFORM="darwin-aarch64"
elif [[ "$OSTYPE" == "linux"* ]]; then
  export OS="linux-x86_64"
  export OS_ARCH="linux-x86_64"
  export  OS_TOOLCHAIN="linux-x86_64"
  export IS_MACOS=false
  export LIB_EXTENSION="so"
  export JNI_PLATFORM="linux-x86_64"
else
  echo "Unsupported operating system: $OSTYPE"
  exit 1
fi

ANDROID_PROJECT_PATH="android"
ANDROID_NDK_PATH="$BUILD_HOME/android/ndk"
export ANDROID_JNI_LIBS_PATH="$BUILD_HOME/$ANDROID_PROJECT_PATH/lib/src/main/jniLibs"
export ANDROID_GENERATED_BINDS_PATH="$BUILD_HOME/$ANDROID_PROJECT_PATH/lib/src/main/kotlin"
ANDROID_MIN_API="27"
export ANDROID_ARCHS=("android-arm64" "android-arm" "android-x86" "android-x86_64")
export ANDROID_TOOLCHAINS=("aarch64-linux-android" "armv7a-linux-androideabi" "i686-linux-android" "x86_64-linux-android")
export ANDROID_JNI=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
OPENSSL_VERSION="openssl-3.2.1"
OPENSSL_PATH="$BUILD_HOME/android/openssl"
OPENSSL_GENERATED_LIBS_PATH="$OPENSSL_PATH-libs"
export IOS_ARCHS=("aarch64-apple-ios" "aarch64-apple-ios-sim" "x86_64-apple-ios")
export PACKAGE_NAME="kos_mobile"

export TARGET_ARCH_INDEX=0  # Default to arm64-v8a
export BINDING_GENERATION_ARCH="${ANDROID_TOOLCHAINS[TARGET_ARCH_INDEX]}"
export BINDING_GENERATION_JNI="${ANDROID_JNI[TARGET_ARCH_INDEX]}"

# colors
export ANDROID='\033[0;92m'
export IOS='\033[0;97m'
RED='\033[0;31m'
GRAY='\033[37m'
NC='\033[0m'
YELLOW='\033[1;33m'

log_warning() {
  echo -e "${YELLOW}$1${NC}"
}

dir_exists() {
  if [ ! -d "$1" ]; then
    return 1
  else
    return 0
  fi
}

file_exists() {
  if [ -f "$1" ]; then
    return 0
  else
    return 1
  fi
}

log_status() {
  echo -e "${GRAY}$1${NC}"
}

log_error() {
  echo -e "${RED}$1${NC}"
}

set_target_architecture() {
  local arch_name=$1
  case "$arch_name" in
    "arm64"|"aarch64")
      export TARGET_ARCH_INDEX=0
      ;;
    "arm"|"armv7")
      export TARGET_ARCH_INDEX=1
      ;;
    "x86")
      export TARGET_ARCH_INDEX=2
      ;;
    "x86_64")
      export TARGET_ARCH_INDEX=3
      ;;
    *)
      log_warning "Unknown architecture: $arch_name. Using default arm64."
      export TARGET_ARCH_INDEX=0
      ;;
  esac
  export BINDING_GENERATION_ARCH="${ANDROID_TOOLCHAINS[TARGET_ARCH_INDEX]}"
  export BINDING_GENERATION_JNI="${ANDROID_JNI[TARGET_ARCH_INDEX]}"
  log_status "Target architecture set to: ${ANDROID_JNI[TARGET_ARCH_INDEX]} (${BINDING_GENERATION_ARCH})"
}

configure_android_ndk() {
  if ! dir_exists "$ANDROID_NDK_PATH"; then
    log_status "configuring ndk..."
    if [ "$IS_MACOS" = true ]; then
      rm -f ndk.dmg
      log_status "starting ndk download for macOS..."
      if ! curl -L https://dl.google.com/android/repository/android-ndk-r28b-darwin.dmg --output "$BUILD_HOME"/ndk.dmg; then
        log_error "Failed to download Android NDK for macOS"
        return 1
      fi
      
      if ! hdiutil attach -quiet -nobrowse -noverify -noautoopen "$BUILD_HOME"/ndk.dmg; then
        log_error "Failed to mount NDK disk image"
        return 1
      fi
      
      mkdir -p "$ANDROID_NDK_PATH"
      log_status "copying ndk files..."
      cp -r /Volumes/Android\ NDK\ r28b/AndroidNDK13356709.app/Contents/NDK/* "$ANDROID_NDK_PATH"
      
      if ! hdiutil detach -quiet /Volumes/Android\ NDK\ r28b/; then
        log_warning "Failed to detach NDK disk image"
      fi
      
      rm ndk.dmg
    else
      rm -f ndk.zip
      log_status "starting ndk download for Linux..."
      if ! curl -L https://dl.google.com/android/repository/android-ndk-r28b-linux.zip --output "$BUILD_HOME"/ndk.zip; then
        log_error "Failed to download Android NDK for Linux"
        return 1
      fi
      
      log_status "extracting ndk files..."
      mkdir -p "$ANDROID_NDK_PATH"
      if ! unzip -q "$BUILD_HOME"/ndk.zip -d "$BUILD_HOME/android"; then
        log_error "Failed to unzip NDK package"
        return 1
      fi
      
      cp -r "$BUILD_HOME"/android/android-ndk-r28b/* "$ANDROID_NDK_PATH"
      rm -rf "$BUILD_HOME"/android/android-ndk-r28b
      rm ndk.zip
    fi
  fi
  export ANDROID_NDK_ROOT="$ANDROID_NDK_PATH"
}

configure_openssl() {
  if ! dir_exists "$OPENSSL_PATH"; then
    log_status "configuring open-ssl..."
    rm -f "$OPENSSL_VERSION".tar.gz
    log_status "starting $OPENSSL_VERSION download..."
    curl -L -o "$OPENSSL_VERSION".tar.gz https://github.com/openssl/openssl/releases/download/"$OPENSSL_VERSION"/"$OPENSSL_VERSION".tar.gz
    tar xfz "${OPENSSL_VERSION}.tar.gz"
    mkdir "$OPENSSL_PATH"
    cp -r "$BUILD_HOME"/"$OPENSSL_VERSION"/* "$OPENSSL_PATH"
    rm -f "$OPENSSL_VERSION".tar.gz
    rm -rf "$OPENSSL_VERSION"
    mkdir -p "$OPENSSL_GENERATED_LIBS_PATH"
  fi
  export OPENSSL_DIR=$OPENSSL_PATH
  export TOOLCHAIN_ROOT="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/$OS"
  export SYSROOT="$TOOLCHAIN_ROOT/sysroot"
  export PATH="$TOOLCHAIN_ROOT/bin:$SYSROOT/usr/local/bin:$PATH"
}

assemble_openssl_lib() {
  arch=$1
  toolchain=$2
  if ! dir_exists "$OPENSSL_GENERATED_LIBS_PATH/$toolchain"; then
    cd "$OPENSSL_PATH" || exit
    log_status "configuring openssl to $toolchain..."
    
    unset CC CXX CXXFLAGS CPPFLAGS
    
    if [ "$arch" = "$OS_ARCH" ]; then
      ./Configure "$arch" no-asm no-shared
    else
      export CC="${TOOLCHAIN_ROOT}/bin/$toolchain${ANDROID_MIN_API}-clang"
      export CXX="${TOOLCHAIN_ROOT}/bin/$toolchain${ANDROID_MIN_API}-clang++"
      export CXXFLAGS="-fPIC"
      export CPPFLAGS="-DANDROID -fPIC"

      export LDFLAGS="-static"
      
      ./Configure "$arch" no-asm no-shared no-stdio
    fi
    log_status "assembling openssl to $toolchain..."
    make clean -s
    if ! make -s; then
      log_error "Failed to build OpenSSL for $toolchain"
      return 1
    fi
    mkdir -p "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
    cp -f libcrypto.a "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
    cp -f libssl.a "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
    
    if ! file_exists "$OPENSSL_GENERATED_LIBS_PATH/$toolchain/libcrypto.a" || ! file_exists "$OPENSSL_GENERATED_LIBS_PATH/$toolchain/libssl.a"; then
      log_error "Failed to create OpenSSL libraries for $toolchain"
      return 1
    fi
    
    log_status "✓ OpenSSL libraries created for $toolchain"
  else
    log_status "skipping assemble openssl to $toolchain..."
  fi
  
  unset CC CXX CXXFLAGS CPPFLAGS LDFLAGS
}

validate_library_arch() {
  local lib_path=$1
  local expected_arch=$2
  
  if file_exists "$lib_path"; then
    local arch_info=$(file "$lib_path")
    log_status "Library info: $arch_info"
    return 0
  else
    log_error "Library not found: $lib_path"
    return 1
  fi
}