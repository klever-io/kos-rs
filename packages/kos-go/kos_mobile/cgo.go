package kos_mobile

/*
#cgo CFLAGS: -I. -I${SRCDIR}
#cgo linux,amd64,!musl LDFLAGS: -L${SRCDIR}/lib/linux-amd64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/linux-amd64
#cgo linux,arm64,!musl LDFLAGS: -L${SRCDIR}/lib/linux-arm64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/linux-arm64
#cgo linux,amd64,musl LDFLAGS: -L${SRCDIR}/lib/linux-musl-amd64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/linux-musl-amd64
#cgo linux,arm64,musl LDFLAGS: -L${SRCDIR}/lib/linux-musl-arm64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/linux-musl-arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin-amd64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/darwin-amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin-aarch64 -lkos_mobile -Wl,-rpath,${SRCDIR}/lib/darwin-aarch64
#include "kos_mobile.h"
#include <stdlib.h>
*/
import "C"
