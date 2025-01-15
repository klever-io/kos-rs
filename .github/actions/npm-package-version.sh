#!/bin/bash
#get highest tag number, and add 0.1.0 if doesn't exist
CURRENT_VERSION=$(git describe --always --long --dirty --tag 2>/dev/null || true)
CURRENT_VERSION="${CURRENT_VERSION}"

echo "Release dev ${CURRENT_VERSION}"

# change version in package.json using jq
jq --arg version "$CURRENT_VERSION" '.version = $version' demo/kos/package.json > tmp.$$.json && mv tmp.$$.json demo/kos/package.json
