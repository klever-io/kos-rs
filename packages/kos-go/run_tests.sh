#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../target/debug"

export CGO_LDFLAGS="-L$LIB_DIR -lkos_mobile"

LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}
export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"

go test -v