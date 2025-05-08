#!/bin/bash

export LIB_DIR=../../target/debug

export CGO_LDFLAGS="-L$LIB_DIR -lkos_mobile"

export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"

go test -v