#!/bin/bash

# build env
BUILD_HOME=$(pwd)
OS="darwin-x86_64"
OS_ARCH="darwin64-arm64-cc"
OS_TOOLCHAIN="darwin-x86_64"
ANDROID_PROJECT_PATH="android"
ANDROID_NDK_PATH="$BUILD_HOME/android/ndk"
ANDROID_JNI_LIBS_PATH="$BUILD_HOME/$ANDROID_PROJECT_PATH/lib/src/main/jniLibs"
ANDROID_GENERATED_BINDS_PATH="$BUILD_HOME/$ANDROID_PROJECT_PATH/lib/src/main/kotlin"
ANDROID_MIN_API="27"
ANDROID_ARCHS=("android-arm64" "android-arm" "android-x86" "android-x86_64")
ANDROID_TOOLCHAINS=("aarch64-linux-android" "armv7a-linux-androideabi" "i686-linux-android" "x86_64-linux-android")
ANDROID_JNI=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
OPENSSL_VERSION="openssl-3.2.1"
OPENSSL_PATH="$BUILD_HOME/android/openssl"
OPENSSL_GENERATED_LIBS_PATH="$OPENSSL_PATH-libs"
IOS_ARCHS=("aarch64-apple-ios" "aarch64-apple-ios-sim" "x86_64-apple-ios")
PACKAGE_NAME="kos_mobile"

# colors
ANDROID='\033[0;92m'
IOS='\033[0;97m'
RED='\033[0;31m'
GRAY='\033[37m'
NC='\033[0m'

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

configure_android_ndk() {
  if ! dir_exists "$ANDROID_NDK_PATH"; then
    log_status "configuring ndk..."
    rm -f ndk.dmg
    log_status "starting ndk download..."
    curl -0 https://dl.google.com/android/repository/android-ndk-r26b-darwin.dmg --output "$BUILD_HOME"/ndk.dmg
    hdiutil attach -quiet -nobrowse -noverify -noautoopen "$BUILD_HOME"/ndk.dmg
    mkdir "$ANDROID_NDK_PATH"
    log_status "copying ndk files..."
    cp -r /Volumes/Android\ NDK\ r26b/AndroidNDK10909125.app/Contents/NDK/* "$ANDROID_NDK_PATH"
    hdiutil detach -quiet /Volumes/Android\ NDK\ r26b/
    rm ndk.dmg
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
    cd "$OPENSSL_PATH"
    log_status "configuring openssl to $toolchain..."
    if [ "$arch" = "$OS_ARCH" ]; then
      ./Configure "$arch" no-asm no-shared
    else
      export CC="${TOOLCHAIN_ROOT}/bin/$toolchain${ANDROID_MIN_API}-clang"
      export CXX="${TOOLCHAIN_ROOT}/bin/$toolchain${ANDROID_MIN_API}-clang++"
      export CXXFLAGS="-fPIC"
      export CPPFLAGS="-DANDROID -fPIC"
      ./Configure "$arch" no-asm no-shared -D__ANDROID_API__="$ANDROID_MIN_API"
    fi
    log_status "assembling openssl to $toolchain..."
    make clean -s
    make -s
    mkdir -p "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
    cp -f libcrypto.a "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
    cp -f libssl.a "$OPENSSL_GENERATED_LIBS_PATH"/"$toolchain"
  else
    log_status "skipping assemble openssl to $toolchain..."
  fi
  export CC=""
  export CXX=""
  export CXXFLAGS=""
  export CPPFLAGS=""
}
