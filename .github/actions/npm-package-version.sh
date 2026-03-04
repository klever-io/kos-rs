#!/usr/bin/env bash

set -Eeuo pipefail

PACKAGE_JSON="packages/kos-web/demo/kos/package.json"

error() {
    echo "Error: $1" >&2
    exit 1
}

cleanup() {
    [[ -f "${TMP_FILE:-}" ]] && rm -f "$TMP_FILE"
}
trap cleanup EXIT

command -v git >/dev/null 2>&1 || error "git not installed"
command -v jq  >/dev/null 2>&1 || error "jq not installed"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || error "Not inside a git repository"

CURRENT_VERSION=$(git describe --always --long --dirty --tag 2>/dev/null || true)

if [[ -z "$CURRENT_VERSION" ]]; then
    echo "ERROR: No git tags found. Using default version 0.1.0"
    CURRENT_VERSION="0.1.0"
fi

echo "Release dev ${CURRENT_VERSION}"

[[ -f "$PACKAGE_JSON" ]] \
    || error "package.json not found at $PACKAGE_JSON"

TMP_FILE=$(mktemp)

jq --arg version "$CURRENT_VERSION" \
   '.version = $version' \
   "$PACKAGE_JSON" > "$TMP_FILE" \
   || error "jq failed to update version"

mv "$TMP_FILE" "$PACKAGE_JSON" \
   || error "Failed to replace package.json"

echo "package.json updated successfully"
