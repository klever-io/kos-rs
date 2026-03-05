#!/usr/bin/env bash

set -Eeuo pipefail

CARGO_TOML="Cargo.toml"
VERSION_FILE="VERSION"

error() {
    echo "ERROR: $1" >&2
    exit 1
}

command -v grep >/dev/null 2>&1 || error "grep not installed"
command -v sed  >/dev/null 2>&1 || error "sed not installed"

[[ -f "$CARGO_TOML" ]] \
    || error "Cargo.toml not found"

CURRENT_VERSION=$(
    grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' "$CARGO_TOML" \
    | head -n1 \
    | sed 's/version = "\(.*\)"/\1/'
) || error "Failed to read version from Cargo.toml"

[[ -n "$CURRENT_VERSION" ]] \
    || error "Version not found in Cargo.toml"

if [[ ! "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Invalid version format: $CURRENT_VERSION"
fi

IFS='.' read -r MAJOR_VERSION MINOR_VERSION PATCH_VERSION <<< "$CURRENT_VERSION" \
    || error "Failed to parse version"

NEW_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}"

echo "Detected version: $NEW_VERSION"

TMP_FILE=$(mktemp)

echo "$NEW_VERSION" > "$TMP_FILE" \
    || error "Failed writing temporary VERSION file"

mv "$TMP_FILE" "$VERSION_FILE" \
    || error "Failed to update VERSION file"

echo "VERSION file updated"
