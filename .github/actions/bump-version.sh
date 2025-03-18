#!/bin/bash

# Get the current version from Cargo.toml
CURRENT_VERSION=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

# Break the version string into an array.
IFS='.' read -ra ADDR <<< "$CURRENT_VERSION"
MAJOR_VERSION=${ADDR[0]}
MINOR_VERSION=${ADDR[1]}
PATCH_VERSION=${ADDR[2]}

NEW_VERSION="$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION"

echo $NEW_VERSION > VERSION
