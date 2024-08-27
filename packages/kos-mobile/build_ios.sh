#!/bin/bash

source build_source.sh

set -o pipefail
set -e

configure_cargo() {
  cd "$BUILD_HOME"
  for i in $(seq 0 $((${#IOS_ARCHS[@]} - 1))); do
    rustup target add "${IOS_ARCHS[i]}" >/dev/null 2>&1
  done
}

assemble_ios_lib() {
  arch=$1
  cd "$BUILD_HOME"
  log_status "assembling iOS lib to $arch..."
  cargo build --target "$arch" --release -q >/dev/null 2>&1
  cd ../../target/"$arch"/release
  mv lib"$PACKAGE_NAME".a "$arch"-lib"$PACKAGE_NAME".a
}

generate_binds() {
  cd "$BUILD_HOME/../.."
  log_status "generating iOS binds..."
  rm -rf ios/binds
  cargo run -q --bin uniffi-bindgen generate --library target/"${IOS_ARCHS[0]}"/release/lib"$PACKAGE_NAME".dylib --language swift --out-dir packages/kos-mobile/ios/binds >/dev/null 2>&1
}

generate_xcframework() {
  log_status "generating XCFramework..."
  cd "$BUILD_HOME"/ios/framework/KOSMobile
  for i in $(seq 0 $((${#IOS_ARCHS[@]} - 1))); do
    rm -rf "${IOS_ARCHS[i]}"
    mkdir -p "${IOS_ARCHS[i]}"/
    if [ "${IOS_ARCHS[i]}" = "aarch64-apple-ios" ]; then
      xcodebuild -project KOSMobile.xcodeproj \
        -scheme KOSMobile \
        -configuration Release \
        -sdk iphoneos \
        -arch arm64 \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        SKIP_INSTALL=NO \
        clean build >/dev/null 2>&1
      BUILT_PRODUCTS_DIR=$(xcodebuild -project KOSMobile.xcodeproj \
        -scheme KOSMobile \
        -configuration Release \
        -sdk iphoneos \
        -arch arm64 \
        -showBuildSettings |
        grep "BUILT_PRODUCTS_DIR" |
        grep -oEi "\/.*")
      cp -f -r "$BUILT_PRODUCTS_DIR"/* "${IOS_ARCHS[i]}"/
    elif [ "${IOS_ARCHS[i]}" = "aarch64-apple-ios-sim" ]; then
      xcodebuild -project KOSMobile.xcodeproj \
        -scheme KOSMobile \
        -configuration Release \
        -sdk iphonesimulator \
        -arch arm64 \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        SKIP_INSTALL=NO \
        clean build >/dev/null 2>&1
      BUILT_PRODUCTS_DIR=$(xcodebuild -project KOSMobile.xcodeproj \
        -scheme KOSMobile \
        -configuration Release \
        -sdk iphonesimulator \
        -arch arm64 \
        -showBuildSettings |
        grep "BUILT_PRODUCTS_DIR" |
        grep -oEi "\/.*")
      cp -f -r "$BUILT_PRODUCTS_DIR"/* "${IOS_ARCHS[i]}"/
    fi
  done
  rm -rf ../../XCFrameworks
  mkdir -p ../../XCFrameworks
  xcodebuild -create-xcframework \
    -framework "${IOS_ARCHS[0]}"/KOSMobile.framework \
    -framework "${IOS_ARCHS[1]}"/KOSMobile.framework \
    -output ../../XCFrameworks/KOSMobile.xcframework >/dev/null 2>&1
  cd ../../XCFrameworks
  zip -r -y KOSMobile.xcframework.zip KOSMobile.xcframework
}

clear
echo -e "${IOS}########################################################${NC}"
echo -e "${IOS}###########  INITIALIZING iOS RUST BUILD  ##############${NC}"
echo -e "${IOS}########################################################${NC}\n"

configure_cargo
for i in $(seq 0 $((${#IOS_ARCHS[@]} - 1))); do
  assemble_ios_lib "${IOS_ARCHS[i]}"
done
generate_binds
generate_xcframework

echo -e "${IOS}iOS RUST BUILD FINISHED 🎉🎉🎉${NC}"
