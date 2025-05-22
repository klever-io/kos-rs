#!/bin/bash

source build_source.sh

set -o pipefail
set -e

configure_cargo() {
  cd "$BUILD_HOME"
  for i in $(seq 0 $((${#IOS_ARCHS[@]} - 1))); do
    rustup target add "${IOS_ARCHS[i]}"
  done
}

assemble_ios_lib() {
  arch=$1
  cd "$BUILD_HOME"
  log_status "assembling iOS lib to $arch..."
  cargo build --target "$arch" --profile mobile
  cd ../../target/"$arch"/mobile
  mv lib"$PACKAGE_NAME".a "$arch"-lib"$PACKAGE_NAME".a
}

generate_binds() {
  cd "$BUILD_HOME/../.."
  log_status "generating iOS binds..."
  rm -rf ios/binds
  cargo run -q --bin uniffi-bindgen generate --library target/"${IOS_ARCHS[0]}"/mobile/lib"$PACKAGE_NAME".dylib --language swift --out-dir packages/kos-mobile/ios/binds
}

generate_xcframework() {
  log_status "generating XCFramework..."
  cd "$BUILD_HOME"/ios
  rm -f ./*.a
  cd "$BUILD_HOME"/../../
  for i in $(seq 0 $((${#IOS_ARCHS[@]} - 1))); do
      cp target/"${IOS_ARCHS[i]}"/mobile/"${IOS_ARCHS[i]}"-lib"$PACKAGE_NAME".a packages/kos-mobile/ios
  done
  cd "$BUILD_HOME"/ios
  lipo -create -output ios-sim-lib"$PACKAGE_NAME".a \
    aarch64-apple-ios-sim-lib"$PACKAGE_NAME".a \
    x86_64-apple-ios-lib"$PACKAGE_NAME".a
  mv aarch64-apple-ios-libkos_mobile.a ios-lib"$PACKAGE_NAME".a
  rm aarch64-apple-ios-sim-lib"$PACKAGE_NAME".a
  rm x86_64-apple-ios-lib"$PACKAGE_NAME".a
  cd "$BUILD_HOME"/ios/framework/KOSMobile
  # Build for physical iOS devices (ARM64)
  xcodebuild -project KOSMobile.xcodeproj \
    -scheme KOSMobile \
    -configuration Release \
    -sdk iphoneos \
    -arch arm64 \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    SKIP_INSTALL=NO \
    clean build
  BUILT_PRODUCTS_DIR=$(xcodebuild -project KOSMobile.xcodeproj \
    -scheme KOSMobile \
    -configuration Release \
    -sdk iphoneos \
    -arch arm64 \
    -showBuildSettings |
    grep "BUILT_PRODUCTS_DIR" |
    grep -oEi "\/.*")
  rm -rf ios-framework
  mkdir ios-framework
  cp -f -r "$BUILT_PRODUCTS_DIR"/* ios-framework/
  # Build for simulators
  xcodebuild -project KOSMobile.xcodeproj \
    -scheme KOSMobile \
    -configuration Release \
    -sdk iphonesimulator \
    -arch arm64 \
    -arch x86_64 \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    SKIP_INSTALL=NO \
    clean build
  BUILT_PRODUCTS_DIR=$(xcodebuild -project KOSMobile.xcodeproj \
    -scheme KOSMobile \
    -configuration Release \
    -sdk iphonesimulator \
    -arch arm64 \
    -arch x86_64 \
    -showBuildSettings |
    grep "BUILT_PRODUCTS_DIR" |
    grep -oEi "\/.*")
  rm -rf ios-sim-framework
  mkdir ios-sim-framework
  cp -f -r "$BUILT_PRODUCTS_DIR"/* ios-sim-framework/
  rm -rf ../../XCFrameworks
  mkdir -p ../../XCFrameworks
  xcodebuild -create-xcframework \
    -framework ios-framework/KOSMobile.framework \
    -debug-symbols "$BUILD_HOME"/ios/framework/KOSMobile/ios-framework/KOSMobile.framework.dSYM \
    -framework ios-sim-framework/KOSMobile.framework \
    -debug-symbols "$BUILD_HOME"/ios/framework/KOSMobile/ios-sim-framework/KOSMobile.framework.dSYM \
    -output ../../XCFrameworks/KOSMobile.xcframework
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