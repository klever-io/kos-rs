#!/bin/bash

# Get the current version from Cargo.toml
CURRENT_VERSION=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

# Break the version string into an array.
IFS='.' read -ra ADDR <<< "$CURRENT_VERSION"
MAJOR_VERSION=${ADDR[0]}
MINOR_VERSION=${ADDR[1]}
PATCH_VERSION=${ADDR[2]}

# Check the PR title to decide how to bump the version.
if [[ "${PR_TITLE}" == "MAJOR:"* ]]; then
  MAJOR_VERSION=$((MAJOR_VERSION + 1))
  MINOR_VERSION=0
  PATCH_VERSION=0
elif [[ "${PR_TITLE}" == "MINOR:"* ]]; then
  MINOR_VERSION=$((MINOR_VERSION + 1))
  PATCH_VERSION=0
else
  PATCH_VERSION=$((PATCH_VERSION + 1))
fi

# Construct the new version string.
NEW_VERSION="$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION"

# Replace the version in Cargo.toml
sed -i "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/g" Cargo.toml

# Print the new version to a file (or alternatively, set it as an environment variable or output variable).
echo $NEW_VERSION > VERSION
   
echo "($PR_TITLE) updating $CURRENT_VERSION to $NEW_VERSION"
