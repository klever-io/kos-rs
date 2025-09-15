#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../target/release"

export CGO_LDFLAGS="-L$LIB_DIR -lkos_mobile"

LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"

export CGO_ENABLED=1

go test -v