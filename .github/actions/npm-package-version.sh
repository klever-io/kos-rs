#!/usr/bin/env bash

set -Eeuo pipefail

PACKAGE_PATH="${1:-packages/kos-web/demo/kos}"
MODE="${2:-}"

# If PACKAGE_PATH is a directory, append package.json
if [[ -d "$PACKAGE_PATH" ]]; then
    PACKAGE_JSON="$PACKAGE_PATH/package.json"
else
    PACKAGE_JSON="$PACKAGE_PATH"
fi

error() {
    echo "Error: $1" >&2
    exit 1
}

cleanup() {
    [[ -f "${TMP_FILE:-}" ]] && rm -f "$TMP_FILE"
}
trap cleanup EXIT

command -v jq >/dev/null 2>&1 || error "jq not installed"

[[ -f "$PACKAGE_JSON" ]] || error "package.json not found at $PACKAGE_JSON"

# 1. Try to get the latest global tag matching v[0-9]*
TAG_VERSION=$(git describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || true)

if [[ -n "$TAG_VERSION" ]]; then
    RAW_VERSION="$TAG_VERSION"
elif [[ -f "Cargo.toml" ]]; then
    RAW_VERSION=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml | head -n1 | sed 's/version = "\(.*\)"/\1/' || true)
else
    RAW_VERSION=$(jq -r '.version // empty' "$PACKAGE_JSON")
fi

# 2. Strictly extract SemVer X.Y.Z
BASE_VERSION=$(echo "${RAW_VERSION:-0.1.0}" | sed -E 's/.*v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

if [[ -z "$BASE_VERSION" || ! "$BASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    BASE_VERSION="0.1.0"
fi

# 3. Apply dev suffix if in dev mode
if [[ "$MODE" == "--dev" || "$MODE" == "dev" ]]; then
    NEW_VERSION="${BASE_VERSION}-dev.$(date +%Y%m%d%H%M%S)"
else
    NEW_VERSION="${BASE_VERSION}"
fi

echo "Setting ${PACKAGE_JSON} version to: ${NEW_VERSION}"

TMP_FILE=$(mktemp)
jq --arg version "$NEW_VERSION" '.version = $version' "$PACKAGE_JSON" > "$TMP_FILE" || error "jq failed to update version"
mv "$TMP_FILE" "$PACKAGE_JSON" || error "Failed to replace package.json"

echo "package.json updated successfully with version ${NEW_VERSION}"
