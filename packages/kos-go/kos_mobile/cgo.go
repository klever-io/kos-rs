package kos_mobile

/*
#cgo CFLAGS: -I.
#cgo linux LDFLAGS: -L./lib/linux-amd64 -lkos_mobile
#cgo darwin,amd64 LDFLAGS: -L./lib/darwin-amd64 -lkos_mobile
#cgo darwin,arm64 LDFLAGS: -L./lib/darwin-aarch64 -lkos_mobile

#include "kos_mobile.h"
#include <stdlib.h>
*/
import "C"
