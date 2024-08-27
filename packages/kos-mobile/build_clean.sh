#!/bin/bash

source build_source.sh

set -o pipefail
set -e

clear_android() {
  rm -rf "$ANDROID_JNI_LIBS_PATH"
  rm -rf "$ANDROID_GENERATED_BINDS_PATH"/uniffi
}

clear_ios() {
  cd "$BUILD_HOME"
  rm -rf ios/XCFrameworks
  rm -rf ios/binds
  rm -rf ios/framework/KOSMobile/aarch64-apple-ios
  rm -rf ios/framework/KOSMobile/aarch64-apple-ios-sim
}

log_status "cleaning android files..."
clear_android
log_status "cleaning iOS files..."
clear_ios

log_status "clear finished!"
