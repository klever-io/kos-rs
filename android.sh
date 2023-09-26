#!/usr/bin/env bash

set -o pipefail
set -e

#  get os name with arch
OS_NAME=$(uname -s);
if [ $OS_NAME = "Darwin" ]; then
  OS_NAME="darwin-x86_64"
elif [ $OS_NAME = "Linux" ]; then
  OS_NAME="linux-x86_64"
else
  echo "Unsupported OS"
  exit 1
fi

export AR=$NDK_HOME/toolchains/llvm/prebuilt/$OS_NAME/bin/llvm-ar

check_env() 
{
  env_var=$1
  # Check if NDK_HOME directory exists
  if [ ! -d "$env_var" ]; then
      echo "$$env_var directory does not exist. Please set NDK_HOME to the correct path."
      exit 1
  fi
}

check_file_exists()
{
  file_path=$1

  # Check if the file exists
  if [ -f "$file_path" ]; then
    echo "File '$file_path' exists."
  else
    echo "File '$file_path' does not exist. Please download it from https://developer.android.com/ndk/downloads and set NDK_HOME to the correct path."
    exit 1;
  fi
}

check_openssl_exists()
{
  if command -v openssl >/dev/null; then
    echo "openssl is installed"

    if [ ! -d "$OPENSSL_DIR" ]; then
      echo "OPENSSL_DIR env is not set. Please set OPENSSL_DIR to the correct path."
      exit 1
    fi

    echo "OPENSSL_DIR env is set"

  else
    echo "openssl is not installed or is not in the PATH env"
    exit 1
  fi
}

build()
{
  arch=$1
  flags=$2
  # if arch is eq armv7a-linux-androideabi
  # then set CC to armv7a-linux-androideabi30-clang
  if [ $arch = "armv7-linux-androideabi" ]; then
    export CC="$NDK_HOME/toolchains/llvm/prebuilt/$OS_NAME/bin/armv7a-linux-androideabi30-clang"
  else
    export CC="$NDK_HOME/toolchains/llvm/prebuilt/$OS_NAME/bin/${arch}30-clang"
  fi

  check_file_exists $CC
  cargo build --manifest-path packages/kos-android/Cargo.toml --target $arch --release $flags
}

echo "Init android build"
echo "Checking NDK_HOME"
check_env $NDK_HOME
check_file_exists $AR
check_openssl_exists

echo "Clean cargo"
cargo clean
rm -rf buid/android

build aarch64-linux-android $1
build i686-linux-android $1
build armv7-linux-androideabi $1
build x86_64-linux-android $1

mkdir -p build/android/aarch64-linux-android \
   build/android/i686-linux-android \
   build/android/armv7-linux-androideabi \
   build/android/x86_64-linux-android

cp target/aarch64-linux-android/release/libkosandroid.so build/android/aarch64-linux-android/libkosandroid.so
cp target/i686-linux-android/release/libkosandroid.so build/android/i686-linux-android/libkosandroid.so
cp target/armv7-linux-androideabi/release/libkosandroid.so build/android/armv7-linux-androideabi/libkosandroid.so
cp target/x86_64-linux-android/release/libkosandroid.so build/android/x86_64-linux-android/libkosandroid.so

