package kos_mobile

/*
#cgo CFLAGS: -I.
#cgo linux LDFLAGS: -L./lib/linux-amd64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/linux-amd64
#cgo darwin,amd64 LDFLAGS: -L./lib/darwin-amd64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/darwin-amd64
#cgo darwin,arm64 LDFLAGS: -L./lib/darwin-aarch64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/darwin-aarch64

#include "kos_mobile.h"
#include <stdlib.h>
*/
import "C"
