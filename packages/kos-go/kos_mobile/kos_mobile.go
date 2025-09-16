package kos_mobile

// #include <kos_mobile.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromExternal(b RustBufferI) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_kos_mobile_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_kos_mobile_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[*E], callback func(*C.RustCallStatus) U) (U, *E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[*E], status C.RustCallStatus) *E {
	switch status.code {
	case 0:
		return nil
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 26
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_kos_mobile_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("kos_mobile: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_absolute()
		})
		if checksum != 63402 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_absolute: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_add()
		})
		if checksum != 977 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_add: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_decrement()
		})
		if checksum != 53089 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_decrement: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_divide()
		})
		if checksum != 28107 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_divide: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_increment()
		})
		if checksum != 4952 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_increment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_equal()
		})
		if checksum != 35658 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_equal: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_gt()
		})
		if checksum != 6998 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_gt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_gte()
		})
		if checksum != 1717 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_gte: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_lt()
		})
		if checksum != 27131 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_lt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_lte()
		})
		if checksum != 32874 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_lte: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_negative()
		})
		if checksum != 23683 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_negative: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_positive()
		})
		if checksum != 63669 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_positive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_is_zero()
		})
		if checksum != 5388 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_is_zero: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_multiply()
		})
		if checksum != 6873 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_multiply: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_new()
		})
		if checksum != 6951 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_new_zero()
		})
		if checksum != 17227 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_new_zero: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_pow()
		})
		if checksum != 42826 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_pow: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_string()
		})
		if checksum != 39006 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_big_number_subtract()
		})
		if checksum != 42165 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_big_number_subtract: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_decrypt()
		})
		if checksum != 30595 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_derive_xpub()
		})
		if checksum != 59242 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_derive_xpub: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_ecies_decrypt()
		})
		if checksum != 8486 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_ecies_decrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_ecies_encrypt()
		})
		if checksum != 52348 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_ecies_encrypt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_encrypt_with_cbc()
		})
		if checksum != 16918 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_encrypt_with_cbc: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_encrypt_with_cfb()
		})
		if checksum != 50604 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_encrypt_with_cfb: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_encrypt_with_gcm()
		})
		if checksum != 63693 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_encrypt_with_gcm: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_generate_mnemonic()
		})
		if checksum != 27040 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_generate_mnemonic: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_generate_wallet_from_mnemonic()
		})
		if checksum != 30857 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_generate_wallet_from_mnemonic: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_generate_wallet_from_private_key()
		})
		if checksum != 1902 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_generate_wallet_from_private_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_generate_xpub()
		})
		if checksum != 14878 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_generate_xpub: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_get_path_by_chain()
		})
		if checksum != 53160 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_get_path_by_chain: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_get_supported_chains()
		})
		if checksum != 3975 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_get_supported_chains: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_get_xpub_as_string()
		})
		if checksum != 2590 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_get_xpub_as_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_hmac_sha256()
		})
		if checksum != 13652 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_hmac_sha256: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_is_chain_supported()
		})
		if checksum != 7669 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_is_chain_supported: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_bitcoin_transaction_options()
		})
		if checksum != 41010 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_bitcoin_transaction_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_cosmos_transaction_options()
		})
		if checksum != 26941 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_cosmos_transaction_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_eth_wallet_options()
		})
		if checksum != 48102 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_eth_wallet_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_evm_transaction_options()
		})
		if checksum != 53286 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_evm_transaction_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_icp_wallet_options()
		})
		if checksum != 63536 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_icp_wallet_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_substrate_transaction_options()
		})
		if checksum != 22686 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_substrate_transaction_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_new_wallet_options()
		})
		if checksum != 7184 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_new_wallet_options: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_sign_ecdsa()
		})
		if checksum != 58121 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_sign_ecdsa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_sign_ecdsa_recoverable()
		})
		if checksum != 64991 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_sign_ecdsa_recoverable: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_sign_message()
		})
		if checksum != 57016 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_sign_message: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_sign_transaction()
		})
		if checksum != 20752 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_sign_transaction: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_slip77_master_blinding_key()
		})
		if checksum != 5170 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_slip77_master_blinding_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_kos_mobile_checksum_func_validate_mnemonic()
		})
		if checksum != 9083 {
			// If this happens try cleaning and rebuilding your project
			panic("kos_mobile: uniffi_kos_mobile_checksum_func_validate_mnemonic: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct{}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterInt64 struct{}

var FfiConverterInt64INSTANCE = FfiConverterInt64{}

func (FfiConverterInt64) Lower(value int64) C.int64_t {
	return C.int64_t(value)
}

func (FfiConverterInt64) Write(writer io.Writer, value int64) {
	writeInt64(writer, value)
}

func (FfiConverterInt64) Lift(value C.int64_t) int64 {
	return int64(value)
}

func (FfiConverterInt64) Read(reader io.Reader) int64 {
	return readInt64(reader)
}

type FfiDestroyerInt64 struct{}

func (FfiDestroyerInt64) Destroy(_ int64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

type BigNumber struct {
	Digits []uint32
	Scale  int64
	Sign   Sign
}

func (r *BigNumber) Destroy() {
	FfiDestroyerSequenceUint32{}.Destroy(r.Digits)
	FfiDestroyerInt64{}.Destroy(r.Scale)
	FfiDestroyerSign{}.Destroy(r.Sign)
}

type FfiConverterBigNumber struct{}

var FfiConverterBigNumberINSTANCE = FfiConverterBigNumber{}

func (c FfiConverterBigNumber) Lift(rb RustBufferI) BigNumber {
	return LiftFromRustBuffer[BigNumber](c, rb)
}

func (c FfiConverterBigNumber) Read(reader io.Reader) BigNumber {
	return BigNumber{
		FfiConverterSequenceUint32INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterSignINSTANCE.Read(reader),
	}
}

func (c FfiConverterBigNumber) Lower(value BigNumber) C.RustBuffer {
	return LowerIntoRustBuffer[BigNumber](c, value)
}

func (c FfiConverterBigNumber) Write(writer io.Writer, value BigNumber) {
	FfiConverterSequenceUint32INSTANCE.Write(writer, value.Digits)
	FfiConverterInt64INSTANCE.Write(writer, value.Scale)
	FfiConverterSignINSTANCE.Write(writer, value.Sign)
}

type FfiDestroyerBigNumber struct{}

func (_ FfiDestroyerBigNumber) Destroy(value BigNumber) {
	value.Destroy()
}

type KosAccount struct {
	ChainId    uint32
	PrivateKey string
	PublicKey  string
	Address    string
	Path       string
	Options    *WalletOptions
}

func (r *KosAccount) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.ChainId)
	FfiDestroyerString{}.Destroy(r.PrivateKey)
	FfiDestroyerString{}.Destroy(r.PublicKey)
	FfiDestroyerString{}.Destroy(r.Address)
	FfiDestroyerString{}.Destroy(r.Path)
	FfiDestroyerOptionalWalletOptions{}.Destroy(r.Options)
}

type FfiConverterKosAccount struct{}

var FfiConverterKosAccountINSTANCE = FfiConverterKosAccount{}

func (c FfiConverterKosAccount) Lift(rb RustBufferI) KosAccount {
	return LiftFromRustBuffer[KosAccount](c, rb)
}

func (c FfiConverterKosAccount) Read(reader io.Reader) KosAccount {
	return KosAccount{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalWalletOptionsINSTANCE.Read(reader),
	}
}

func (c FfiConverterKosAccount) Lower(value KosAccount) C.RustBuffer {
	return LowerIntoRustBuffer[KosAccount](c, value)
}

func (c FfiConverterKosAccount) Write(writer io.Writer, value KosAccount) {
	FfiConverterUint32INSTANCE.Write(writer, value.ChainId)
	FfiConverterStringINSTANCE.Write(writer, value.PrivateKey)
	FfiConverterStringINSTANCE.Write(writer, value.PublicKey)
	FfiConverterStringINSTANCE.Write(writer, value.Address)
	FfiConverterStringINSTANCE.Write(writer, value.Path)
	FfiConverterOptionalWalletOptionsINSTANCE.Write(writer, value.Options)
}

type FfiDestroyerKosAccount struct{}

func (_ FfiDestroyerKosAccount) Destroy(value KosAccount) {
	value.Destroy()
}

type KosTransaction struct {
	ChainId   uint32
	Raw       string
	Sender    string
	Signature string
}

func (r *KosTransaction) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.ChainId)
	FfiDestroyerString{}.Destroy(r.Raw)
	FfiDestroyerString{}.Destroy(r.Sender)
	FfiDestroyerString{}.Destroy(r.Signature)
}

type FfiConverterKosTransaction struct{}

var FfiConverterKosTransactionINSTANCE = FfiConverterKosTransaction{}

func (c FfiConverterKosTransaction) Lift(rb RustBufferI) KosTransaction {
	return LiftFromRustBuffer[KosTransaction](c, rb)
}

func (c FfiConverterKosTransaction) Read(reader io.Reader) KosTransaction {
	return KosTransaction{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterKosTransaction) Lower(value KosTransaction) C.RustBuffer {
	return LowerIntoRustBuffer[KosTransaction](c, value)
}

func (c FfiConverterKosTransaction) Write(writer io.Writer, value KosTransaction) {
	FfiConverterUint32INSTANCE.Write(writer, value.ChainId)
	FfiConverterStringINSTANCE.Write(writer, value.Raw)
	FfiConverterStringINSTANCE.Write(writer, value.Sender)
	FfiConverterStringINSTANCE.Write(writer, value.Signature)
}

type FfiDestroyerKosTransaction struct{}

func (_ FfiDestroyerKosTransaction) Destroy(value KosTransaction) {
	value.Destroy()
}

type WalletOptions struct {
	UseLegacyPath bool
	Specific      *WalletChainOptions
}

func (r *WalletOptions) Destroy() {
	FfiDestroyerBool{}.Destroy(r.UseLegacyPath)
	FfiDestroyerOptionalWalletChainOptions{}.Destroy(r.Specific)
}

type FfiConverterWalletOptions struct{}

var FfiConverterWalletOptionsINSTANCE = FfiConverterWalletOptions{}

func (c FfiConverterWalletOptions) Lift(rb RustBufferI) WalletOptions {
	return LiftFromRustBuffer[WalletOptions](c, rb)
}

func (c FfiConverterWalletOptions) Read(reader io.Reader) WalletOptions {
	return WalletOptions{
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalWalletChainOptionsINSTANCE.Read(reader),
	}
}

func (c FfiConverterWalletOptions) Lower(value WalletOptions) C.RustBuffer {
	return LowerIntoRustBuffer[WalletOptions](c, value)
}

func (c FfiConverterWalletOptions) Write(writer io.Writer, value WalletOptions) {
	FfiConverterBoolINSTANCE.Write(writer, value.UseLegacyPath)
	FfiConverterOptionalWalletChainOptionsINSTANCE.Write(writer, value.Specific)
}

type FfiDestroyerWalletOptions struct{}

func (_ FfiDestroyerWalletOptions) Destroy(value WalletOptions) {
	value.Destroy()
}

type KosError struct {
	err error
}

// Convience method to turn *KosError into error
// Avoiding treating nil pointer as non nil error interface
func (err *KosError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err KosError) Error() string {
	return fmt.Sprintf("KosError: %s", err.err.Error())
}

func (err KosError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrKosErrorUnsupportedChain = fmt.Errorf("KosErrorUnsupportedChain")
var ErrKosErrorKosDelegate = fmt.Errorf("KosErrorKosDelegate")
var ErrKosErrorHexDecode = fmt.Errorf("KosErrorHexDecode")
var ErrKosErrorKosNumber = fmt.Errorf("KosErrorKosNumber")

// Variant structs
type KosErrorUnsupportedChain struct {
	Id string
}

func NewKosErrorUnsupportedChain(
	id string,
) *KosError {
	return &KosError{err: &KosErrorUnsupportedChain{
		Id: id}}
}

func (e KosErrorUnsupportedChain) destroy() {
	FfiDestroyerString{}.Destroy(e.Id)
}

func (err KosErrorUnsupportedChain) Error() string {
	return fmt.Sprint("UnsupportedChain",
		": ",

		"Id=",
		err.Id,
	)
}

func (self KosErrorUnsupportedChain) Is(target error) bool {
	return target == ErrKosErrorUnsupportedChain
}

type KosErrorKosDelegate struct {
	Field0 string
}

func NewKosErrorKosDelegate(
	var0 string,
) *KosError {
	return &KosError{err: &KosErrorKosDelegate{
		Field0: var0}}
}

func (e KosErrorKosDelegate) destroy() {
	FfiDestroyerString{}.Destroy(e.Field0)
}

func (err KosErrorKosDelegate) Error() string {
	return fmt.Sprint("KosDelegate",
		": ",

		"Field0=",
		err.Field0,
	)
}

func (self KosErrorKosDelegate) Is(target error) bool {
	return target == ErrKosErrorKosDelegate
}

type KosErrorHexDecode struct {
	Field0 string
}

func NewKosErrorHexDecode(
	var0 string,
) *KosError {
	return &KosError{err: &KosErrorHexDecode{
		Field0: var0}}
}

func (e KosErrorHexDecode) destroy() {
	FfiDestroyerString{}.Destroy(e.Field0)
}

func (err KosErrorHexDecode) Error() string {
	return fmt.Sprint("HexDecode",
		": ",

		"Field0=",
		err.Field0,
	)
}

func (self KosErrorHexDecode) Is(target error) bool {
	return target == ErrKosErrorHexDecode
}

type KosErrorKosNumber struct {
	Field0 string
}

func NewKosErrorKosNumber(
	var0 string,
) *KosError {
	return &KosError{err: &KosErrorKosNumber{
		Field0: var0}}
}

func (e KosErrorKosNumber) destroy() {
	FfiDestroyerString{}.Destroy(e.Field0)
}

func (err KosErrorKosNumber) Error() string {
	return fmt.Sprint("KosNumber",
		": ",

		"Field0=",
		err.Field0,
	)
}

func (self KosErrorKosNumber) Is(target error) bool {
	return target == ErrKosErrorKosNumber
}

type FfiConverterKosError struct{}

var FfiConverterKosErrorINSTANCE = FfiConverterKosError{}

func (c FfiConverterKosError) Lift(eb RustBufferI) *KosError {
	return LiftFromRustBuffer[*KosError](c, eb)
}

func (c FfiConverterKosError) Lower(value *KosError) C.RustBuffer {
	return LowerIntoRustBuffer[*KosError](c, value)
}

func (c FfiConverterKosError) Read(reader io.Reader) *KosError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &KosError{&KosErrorUnsupportedChain{
			Id: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 2:
		return &KosError{&KosErrorKosDelegate{
			Field0: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 3:
		return &KosError{&KosErrorHexDecode{
			Field0: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 4:
		return &KosError{&KosErrorKosNumber{
			Field0: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterKosError.Read()", errorID))
	}
}

func (c FfiConverterKosError) Write(writer io.Writer, value *KosError) {
	switch variantValue := value.err.(type) {
	case *KosErrorUnsupportedChain:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Id)
	case *KosErrorKosDelegate:
		writeInt32(writer, 2)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Field0)
	case *KosErrorHexDecode:
		writeInt32(writer, 3)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Field0)
	case *KosErrorKosNumber:
		writeInt32(writer, 4)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Field0)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterKosError.Write", value))
	}
}

type FfiDestroyerKosError struct{}

func (_ FfiDestroyerKosError) Destroy(value *KosError) {
	switch variantValue := value.err.(type) {
	case KosErrorUnsupportedChain:
		variantValue.destroy()
	case KosErrorKosDelegate:
		variantValue.destroy()
	case KosErrorHexDecode:
		variantValue.destroy()
	case KosErrorKosNumber:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerKosError.Destroy", value))
	}
}

type LdError struct {
	err error
}

// Convience method to turn *LdError into error
// Avoiding treating nil pointer as non nil error interface
func (err *LdError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err LdError) Error() string {
	return fmt.Sprintf("LdError: %s", err.err.Error())
}

func (err LdError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrLdErrorMnemonicError = fmt.Errorf("LdErrorMnemonicError")
var ErrLdErrorIntanceError = fmt.Errorf("LdErrorIntanceError")
var ErrLdErrorSignerError = fmt.Errorf("LdErrorSignerError")
var ErrLdErrorGeneric = fmt.Errorf("LdErrorGeneric")
var ErrLdErrorDerivationError = fmt.Errorf("LdErrorDerivationError")
var ErrLdErrorInvalidIndex = fmt.Errorf("LdErrorInvalidIndex")

// Variant structs
type LdErrorMnemonicError struct {
}

func NewLdErrorMnemonicError() *LdError {
	return &LdError{err: &LdErrorMnemonicError{}}
}

func (e LdErrorMnemonicError) destroy() {
}

func (err LdErrorMnemonicError) Error() string {
	return fmt.Sprint("MnemonicError")
}

func (self LdErrorMnemonicError) Is(target error) bool {
	return target == ErrLdErrorMnemonicError
}

type LdErrorIntanceError struct {
}

func NewLdErrorIntanceError() *LdError {
	return &LdError{err: &LdErrorIntanceError{}}
}

func (e LdErrorIntanceError) destroy() {
}

func (err LdErrorIntanceError) Error() string {
	return fmt.Sprint("IntanceError")
}

func (self LdErrorIntanceError) Is(target error) bool {
	return target == ErrLdErrorIntanceError
}

type LdErrorSignerError struct {
}

func NewLdErrorSignerError() *LdError {
	return &LdError{err: &LdErrorSignerError{}}
}

func (e LdErrorSignerError) destroy() {
}

func (err LdErrorSignerError) Error() string {
	return fmt.Sprint("SignerError")
}

func (self LdErrorSignerError) Is(target error) bool {
	return target == ErrLdErrorSignerError
}

type LdErrorGeneric struct {
	Err string
}

func NewLdErrorGeneric(
	err string,
) *LdError {
	return &LdError{err: &LdErrorGeneric{
		Err: err}}
}

func (e LdErrorGeneric) destroy() {
	FfiDestroyerString{}.Destroy(e.Err)
}

func (err LdErrorGeneric) Error() string {
	return fmt.Sprint("Generic",
		": ",

		"Err=",
		err.Err,
	)
}

func (self LdErrorGeneric) Is(target error) bool {
	return target == ErrLdErrorGeneric
}

type LdErrorDerivationError struct {
}

func NewLdErrorDerivationError() *LdError {
	return &LdError{err: &LdErrorDerivationError{}}
}

func (e LdErrorDerivationError) destroy() {
}

func (err LdErrorDerivationError) Error() string {
	return fmt.Sprint("DerivationError")
}

func (self LdErrorDerivationError) Is(target error) bool {
	return target == ErrLdErrorDerivationError
}

type LdErrorInvalidIndex struct {
	Field0 uint32
}

func NewLdErrorInvalidIndex(
	var0 uint32,
) *LdError {
	return &LdError{err: &LdErrorInvalidIndex{
		Field0: var0}}
}

func (e LdErrorInvalidIndex) destroy() {
	FfiDestroyerUint32{}.Destroy(e.Field0)
}

func (err LdErrorInvalidIndex) Error() string {
	return fmt.Sprint("InvalidIndex",
		": ",

		"Field0=",
		err.Field0,
	)
}

func (self LdErrorInvalidIndex) Is(target error) bool {
	return target == ErrLdErrorInvalidIndex
}

type FfiConverterLdError struct{}

var FfiConverterLdErrorINSTANCE = FfiConverterLdError{}

func (c FfiConverterLdError) Lift(eb RustBufferI) *LdError {
	return LiftFromRustBuffer[*LdError](c, eb)
}

func (c FfiConverterLdError) Lower(value *LdError) C.RustBuffer {
	return LowerIntoRustBuffer[*LdError](c, value)
}

func (c FfiConverterLdError) Read(reader io.Reader) *LdError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &LdError{&LdErrorMnemonicError{}}
	case 2:
		return &LdError{&LdErrorIntanceError{}}
	case 3:
		return &LdError{&LdErrorSignerError{}}
	case 4:
		return &LdError{&LdErrorGeneric{
			Err: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 5:
		return &LdError{&LdErrorDerivationError{}}
	case 6:
		return &LdError{&LdErrorInvalidIndex{
			Field0: FfiConverterUint32INSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterLdError.Read()", errorID))
	}
}

func (c FfiConverterLdError) Write(writer io.Writer, value *LdError) {
	switch variantValue := value.err.(type) {
	case *LdErrorMnemonicError:
		writeInt32(writer, 1)
	case *LdErrorIntanceError:
		writeInt32(writer, 2)
	case *LdErrorSignerError:
		writeInt32(writer, 3)
	case *LdErrorGeneric:
		writeInt32(writer, 4)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Err)
	case *LdErrorDerivationError:
		writeInt32(writer, 5)
	case *LdErrorInvalidIndex:
		writeInt32(writer, 6)
		FfiConverterUint32INSTANCE.Write(writer, variantValue.Field0)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterLdError.Write", value))
	}
}

type FfiDestroyerLdError struct{}

func (_ FfiDestroyerLdError) Destroy(value *LdError) {
	switch variantValue := value.err.(type) {
	case LdErrorMnemonicError:
		variantValue.destroy()
	case LdErrorIntanceError:
		variantValue.destroy()
	case LdErrorSignerError:
		variantValue.destroy()
	case LdErrorGeneric:
		variantValue.destroy()
	case LdErrorDerivationError:
		variantValue.destroy()
	case LdErrorInvalidIndex:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerLdError.Destroy", value))
	}
}

type Sign uint

const (
	SignMinus  Sign = 1
	SignNoSign Sign = 2
	SignPlus   Sign = 3
)

type FfiConverterSign struct{}

var FfiConverterSignINSTANCE = FfiConverterSign{}

func (c FfiConverterSign) Lift(rb RustBufferI) Sign {
	return LiftFromRustBuffer[Sign](c, rb)
}

func (c FfiConverterSign) Lower(value Sign) C.RustBuffer {
	return LowerIntoRustBuffer[Sign](c, value)
}
func (FfiConverterSign) Read(reader io.Reader) Sign {
	id := readInt32(reader)
	return Sign(id)
}

func (FfiConverterSign) Write(writer io.Writer, value Sign) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerSign struct{}

func (_ FfiDestroyerSign) Destroy(value Sign) {
}

type TransactionChainOptions interface {
	Destroy()
}
type TransactionChainOptionsEvm struct {
	ChainId uint32
}

func (e TransactionChainOptionsEvm) Destroy() {
	FfiDestroyerUint32{}.Destroy(e.ChainId)
}

type TransactionChainOptionsBtc struct {
	PrevScripts  [][]byte
	InputAmounts []uint64
}

func (e TransactionChainOptionsBtc) Destroy() {
	FfiDestroyerSequenceBytes{}.Destroy(e.PrevScripts)
	FfiDestroyerSequenceUint64{}.Destroy(e.InputAmounts)
}

type TransactionChainOptionsSubstrate struct {
	Call               []byte
	Era                []byte
	Nonce              uint32
	Tip                uint64
	BlockHash          []byte
	GenesisHash        []byte
	SpecVersion        uint32
	TransactionVersion uint32
	AppId              *uint32
}

func (e TransactionChainOptionsSubstrate) Destroy() {
	FfiDestroyerBytes{}.Destroy(e.Call)
	FfiDestroyerBytes{}.Destroy(e.Era)
	FfiDestroyerUint32{}.Destroy(e.Nonce)
	FfiDestroyerUint64{}.Destroy(e.Tip)
	FfiDestroyerBytes{}.Destroy(e.BlockHash)
	FfiDestroyerBytes{}.Destroy(e.GenesisHash)
	FfiDestroyerUint32{}.Destroy(e.SpecVersion)
	FfiDestroyerUint32{}.Destroy(e.TransactionVersion)
	FfiDestroyerOptionalUint32{}.Destroy(e.AppId)
}

type TransactionChainOptionsCosmos struct {
	ChainId       string
	AccountNumber uint64
}

func (e TransactionChainOptionsCosmos) Destroy() {
	FfiDestroyerString{}.Destroy(e.ChainId)
	FfiDestroyerUint64{}.Destroy(e.AccountNumber)
}

type FfiConverterTransactionChainOptions struct{}

var FfiConverterTransactionChainOptionsINSTANCE = FfiConverterTransactionChainOptions{}

func (c FfiConverterTransactionChainOptions) Lift(rb RustBufferI) TransactionChainOptions {
	return LiftFromRustBuffer[TransactionChainOptions](c, rb)
}

func (c FfiConverterTransactionChainOptions) Lower(value TransactionChainOptions) C.RustBuffer {
	return LowerIntoRustBuffer[TransactionChainOptions](c, value)
}
func (FfiConverterTransactionChainOptions) Read(reader io.Reader) TransactionChainOptions {
	id := readInt32(reader)
	switch id {
	case 1:
		return TransactionChainOptionsEvm{
			FfiConverterUint32INSTANCE.Read(reader),
		}
	case 2:
		return TransactionChainOptionsBtc{
			FfiConverterSequenceBytesINSTANCE.Read(reader),
			FfiConverterSequenceUint64INSTANCE.Read(reader),
		}
	case 3:
		return TransactionChainOptionsSubstrate{
			FfiConverterBytesINSTANCE.Read(reader),
			FfiConverterBytesINSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
			FfiConverterBytesINSTANCE.Read(reader),
			FfiConverterBytesINSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterUint32INSTANCE.Read(reader),
			FfiConverterOptionalUint32INSTANCE.Read(reader),
		}
	case 4:
		return TransactionChainOptionsCosmos{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterUint64INSTANCE.Read(reader),
		}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterTransactionChainOptions.Read()", id))
	}
}

func (FfiConverterTransactionChainOptions) Write(writer io.Writer, value TransactionChainOptions) {
	switch variant_value := value.(type) {
	case TransactionChainOptionsEvm:
		writeInt32(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.ChainId)
	case TransactionChainOptionsBtc:
		writeInt32(writer, 2)
		FfiConverterSequenceBytesINSTANCE.Write(writer, variant_value.PrevScripts)
		FfiConverterSequenceUint64INSTANCE.Write(writer, variant_value.InputAmounts)
	case TransactionChainOptionsSubstrate:
		writeInt32(writer, 3)
		FfiConverterBytesINSTANCE.Write(writer, variant_value.Call)
		FfiConverterBytesINSTANCE.Write(writer, variant_value.Era)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.Nonce)
		FfiConverterUint64INSTANCE.Write(writer, variant_value.Tip)
		FfiConverterBytesINSTANCE.Write(writer, variant_value.BlockHash)
		FfiConverterBytesINSTANCE.Write(writer, variant_value.GenesisHash)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.SpecVersion)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.TransactionVersion)
		FfiConverterOptionalUint32INSTANCE.Write(writer, variant_value.AppId)
	case TransactionChainOptionsCosmos:
		writeInt32(writer, 4)
		FfiConverterStringINSTANCE.Write(writer, variant_value.ChainId)
		FfiConverterUint64INSTANCE.Write(writer, variant_value.AccountNumber)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterTransactionChainOptions.Write", value))
	}
}

type FfiDestroyerTransactionChainOptions struct{}

func (_ FfiDestroyerTransactionChainOptions) Destroy(value TransactionChainOptions) {
	value.Destroy()
}

type WalletChainOptions interface {
	Destroy()
}
type WalletChainOptionsCustomEth struct {
	ChainId uint32
}

func (e WalletChainOptionsCustomEth) Destroy() {
	FfiDestroyerUint32{}.Destroy(e.ChainId)
}

type WalletChainOptionsCustomIcp struct {
	KeyType string
}

func (e WalletChainOptionsCustomIcp) Destroy() {
	FfiDestroyerString{}.Destroy(e.KeyType)
}

type FfiConverterWalletChainOptions struct{}

var FfiConverterWalletChainOptionsINSTANCE = FfiConverterWalletChainOptions{}

func (c FfiConverterWalletChainOptions) Lift(rb RustBufferI) WalletChainOptions {
	return LiftFromRustBuffer[WalletChainOptions](c, rb)
}

func (c FfiConverterWalletChainOptions) Lower(value WalletChainOptions) C.RustBuffer {
	return LowerIntoRustBuffer[WalletChainOptions](c, value)
}
func (FfiConverterWalletChainOptions) Read(reader io.Reader) WalletChainOptions {
	id := readInt32(reader)
	switch id {
	case 1:
		return WalletChainOptionsCustomEth{
			FfiConverterUint32INSTANCE.Read(reader),
		}
	case 2:
		return WalletChainOptionsCustomIcp{
			FfiConverterStringINSTANCE.Read(reader),
		}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterWalletChainOptions.Read()", id))
	}
}

func (FfiConverterWalletChainOptions) Write(writer io.Writer, value WalletChainOptions) {
	switch variant_value := value.(type) {
	case WalletChainOptionsCustomEth:
		writeInt32(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.ChainId)
	case WalletChainOptionsCustomIcp:
		writeInt32(writer, 2)
		FfiConverterStringINSTANCE.Write(writer, variant_value.KeyType)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterWalletChainOptions.Write", value))
	}
}

type FfiDestroyerWalletChainOptions struct{}

func (_ FfiDestroyerWalletChainOptions) Destroy(value WalletChainOptions) {
	value.Destroy()
}

type FfiConverterOptionalUint32 struct{}

var FfiConverterOptionalUint32INSTANCE = FfiConverterOptionalUint32{}

func (c FfiConverterOptionalUint32) Lift(rb RustBufferI) *uint32 {
	return LiftFromRustBuffer[*uint32](c, rb)
}

func (_ FfiConverterOptionalUint32) Read(reader io.Reader) *uint32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint32) Lower(value *uint32) C.RustBuffer {
	return LowerIntoRustBuffer[*uint32](c, value)
}

func (_ FfiConverterOptionalUint32) Write(writer io.Writer, value *uint32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint32 struct{}

func (_ FfiDestroyerOptionalUint32) Destroy(value *uint32) {
	if value != nil {
		FfiDestroyerUint32{}.Destroy(*value)
	}
}

type FfiConverterOptionalWalletOptions struct{}

var FfiConverterOptionalWalletOptionsINSTANCE = FfiConverterOptionalWalletOptions{}

func (c FfiConverterOptionalWalletOptions) Lift(rb RustBufferI) *WalletOptions {
	return LiftFromRustBuffer[*WalletOptions](c, rb)
}

func (_ FfiConverterOptionalWalletOptions) Read(reader io.Reader) *WalletOptions {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWalletOptionsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWalletOptions) Lower(value *WalletOptions) C.RustBuffer {
	return LowerIntoRustBuffer[*WalletOptions](c, value)
}

func (_ FfiConverterOptionalWalletOptions) Write(writer io.Writer, value *WalletOptions) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWalletOptionsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWalletOptions struct{}

func (_ FfiDestroyerOptionalWalletOptions) Destroy(value *WalletOptions) {
	if value != nil {
		FfiDestroyerWalletOptions{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransactionChainOptions struct{}

var FfiConverterOptionalTransactionChainOptionsINSTANCE = FfiConverterOptionalTransactionChainOptions{}

func (c FfiConverterOptionalTransactionChainOptions) Lift(rb RustBufferI) *TransactionChainOptions {
	return LiftFromRustBuffer[*TransactionChainOptions](c, rb)
}

func (_ FfiConverterOptionalTransactionChainOptions) Read(reader io.Reader) *TransactionChainOptions {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransactionChainOptionsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransactionChainOptions) Lower(value *TransactionChainOptions) C.RustBuffer {
	return LowerIntoRustBuffer[*TransactionChainOptions](c, value)
}

func (_ FfiConverterOptionalTransactionChainOptions) Write(writer io.Writer, value *TransactionChainOptions) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransactionChainOptionsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransactionChainOptions struct{}

func (_ FfiDestroyerOptionalTransactionChainOptions) Destroy(value *TransactionChainOptions) {
	if value != nil {
		FfiDestroyerTransactionChainOptions{}.Destroy(*value)
	}
}

type FfiConverterOptionalWalletChainOptions struct{}

var FfiConverterOptionalWalletChainOptionsINSTANCE = FfiConverterOptionalWalletChainOptions{}

func (c FfiConverterOptionalWalletChainOptions) Lift(rb RustBufferI) *WalletChainOptions {
	return LiftFromRustBuffer[*WalletChainOptions](c, rb)
}

func (_ FfiConverterOptionalWalletChainOptions) Read(reader io.Reader) *WalletChainOptions {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWalletChainOptionsINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWalletChainOptions) Lower(value *WalletChainOptions) C.RustBuffer {
	return LowerIntoRustBuffer[*WalletChainOptions](c, value)
}

func (_ FfiConverterOptionalWalletChainOptions) Write(writer io.Writer, value *WalletChainOptions) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWalletChainOptionsINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWalletChainOptions struct{}

func (_ FfiDestroyerOptionalWalletChainOptions) Destroy(value *WalletChainOptions) {
	if value != nil {
		FfiDestroyerWalletChainOptions{}.Destroy(*value)
	}
}

type FfiConverterSequenceUint32 struct{}

var FfiConverterSequenceUint32INSTANCE = FfiConverterSequenceUint32{}

func (c FfiConverterSequenceUint32) Lift(rb RustBufferI) []uint32 {
	return LiftFromRustBuffer[[]uint32](c, rb)
}

func (c FfiConverterSequenceUint32) Read(reader io.Reader) []uint32 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint32, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint32INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint32) Lower(value []uint32) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint32](c, value)
}

func (c FfiConverterSequenceUint32) Write(writer io.Writer, value []uint32) {
	if len(value) > math.MaxInt32 {
		panic("[]uint32 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint32INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint32 struct{}

func (FfiDestroyerSequenceUint32) Destroy(sequence []uint32) {
	for _, value := range sequence {
		FfiDestroyerUint32{}.Destroy(value)
	}
}

type FfiConverterSequenceUint64 struct{}

var FfiConverterSequenceUint64INSTANCE = FfiConverterSequenceUint64{}

func (c FfiConverterSequenceUint64) Lift(rb RustBufferI) []uint64 {
	return LiftFromRustBuffer[[]uint64](c, rb)
}

func (c FfiConverterSequenceUint64) Read(reader io.Reader) []uint64 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint64, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint64INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint64) Lower(value []uint64) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint64](c, value)
}

func (c FfiConverterSequenceUint64) Write(writer io.Writer, value []uint64) {
	if len(value) > math.MaxInt32 {
		panic("[]uint64 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint64INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint64 struct{}

func (FfiDestroyerSequenceUint64) Destroy(sequence []uint64) {
	for _, value := range sequence {
		FfiDestroyerUint64{}.Destroy(value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterSequenceBytes struct{}

var FfiConverterSequenceBytesINSTANCE = FfiConverterSequenceBytes{}

func (c FfiConverterSequenceBytes) Lift(rb RustBufferI) [][]byte {
	return LiftFromRustBuffer[[][]byte](c, rb)
}

func (c FfiConverterSequenceBytes) Read(reader io.Reader) [][]byte {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([][]byte, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterBytesINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceBytes) Lower(value [][]byte) C.RustBuffer {
	return LowerIntoRustBuffer[[][]byte](c, value)
}

func (c FfiConverterSequenceBytes) Write(writer io.Writer, value [][]byte) {
	if len(value) > math.MaxInt32 {
		panic("[][]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterBytesINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceBytes struct{}

func (FfiDestroyerSequenceBytes) Destroy(sequence [][]byte) {
	for _, value := range sequence {
		FfiDestroyerBytes{}.Destroy(value)
	}
}

func BigNumberAbsolute(value BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_absolute(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberAdd(lhs BigNumber, rhs BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_add(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberDecrement(value BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_decrement(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberDivide(lhs BigNumber, rhs BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_divide(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberIncrement(value BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_increment(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberIsEqual(lhs BigNumber, rhs BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_equal(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func BigNumberIsGt(lhs BigNumber, rhs BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_gt(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func BigNumberIsGte(lhs BigNumber, rhs BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_gte(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func BigNumberIsLt(lhs BigNumber, rhs BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_lt(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func BigNumberIsLte(lhs BigNumber, rhs BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_lte(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus)
	}))
}

func BigNumberIsNegative(value BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_negative(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus)
	}))
}

func BigNumberIsPositive(value BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_positive(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus)
	}))
}

func BigNumberIsZero(value BigNumber) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_big_number_is_zero(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus)
	}))
}

func BigNumberMultiply(lhs BigNumber, rhs BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_multiply(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberNew(value string) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_new(FfiConverterStringINSTANCE.Lower(value), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberNewZero() BigNumber {
	return FfiConverterBigNumberINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_new_zero(_uniffiStatus),
		}
	}))
}

func BigNumberPow(base BigNumber, exponent BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_pow(FfiConverterBigNumberINSTANCE.Lower(base), FfiConverterBigNumberINSTANCE.Lower(exponent), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func BigNumberString(value BigNumber) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_string(FfiConverterBigNumberINSTANCE.Lower(value), _uniffiStatus),
		}
	}))
}

func BigNumberSubtract(lhs BigNumber, rhs BigNumber) (BigNumber, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_big_number_subtract(FfiConverterBigNumberINSTANCE.Lower(lhs), FfiConverterBigNumberINSTANCE.Lower(rhs), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BigNumber
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBigNumberINSTANCE.Lift(_uniffiRV), nil
	}
}

func Decrypt(data string, password string, iterations uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_decrypt(FfiConverterStringINSTANCE.Lower(data), FfiConverterStringINSTANCE.Lower(password), FfiConverterUint32INSTANCE.Lower(iterations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func DeriveXpub(mnemonic string, passphrase string, isMainnet bool, index uint32, derivationPath string) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_derive_xpub(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterStringINSTANCE.Lower(derivationPath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func EciesDecrypt(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_ecies_decrypt(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterBytesINSTANCE.Lower(msg), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func EciesEncrypt(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_ecies_encrypt(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterBytesINSTANCE.Lower(msg), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func EncryptWithCbc(data string, password string, iterations uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_encrypt_with_cbc(FfiConverterStringINSTANCE.Lower(data), FfiConverterStringINSTANCE.Lower(password), FfiConverterUint32INSTANCE.Lower(iterations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func EncryptWithCfb(data string, password string, iterations uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_encrypt_with_cfb(FfiConverterStringINSTANCE.Lower(data), FfiConverterStringINSTANCE.Lower(password), FfiConverterUint32INSTANCE.Lower(iterations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func EncryptWithGcm(data string, password string, iterations uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_encrypt_with_gcm(FfiConverterStringINSTANCE.Lower(data), FfiConverterStringINSTANCE.Lower(password), FfiConverterUint32INSTANCE.Lower(iterations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func GenerateMnemonic(size int32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_generate_mnemonic(FfiConverterInt32INSTANCE.Lower(size), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func GenerateWalletFromMnemonic(mnemonic string, chainId uint32, index uint32, options *WalletOptions) (KosAccount, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_generate_wallet_from_mnemonic(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterUint32INSTANCE.Lower(chainId), FfiConverterUint32INSTANCE.Lower(index), FfiConverterOptionalWalletOptionsINSTANCE.Lower(options), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue KosAccount
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterKosAccountINSTANCE.Lift(_uniffiRV), nil
	}
}

func GenerateWalletFromPrivateKey(chainId uint32, privateKey string, options *WalletOptions) (KosAccount, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_generate_wallet_from_private_key(FfiConverterUint32INSTANCE.Lower(chainId), FfiConverterStringINSTANCE.Lower(privateKey), FfiConverterOptionalWalletOptionsINSTANCE.Lower(options), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue KosAccount
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterKosAccountINSTANCE.Lift(_uniffiRV), nil
	}
}

func GenerateXpub(mnemonic string, passphrase string, isMainnet bool, index uint32) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_generate_xpub(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func GetPathByChain(chainId uint32, index uint32, useLegacyPath bool) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_get_path_by_chain(FfiConverterUint32INSTANCE.Lower(chainId), FfiConverterUint32INSTANCE.Lower(index), FfiConverterBoolINSTANCE.Lower(useLegacyPath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func GetSupportedChains() []uint32 {
	return FfiConverterSequenceUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_get_supported_chains(_uniffiStatus),
		}
	}))
}

func GetXpubAsString(mnemonic string, passphrase string, isMainnet bool, index uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_get_xpub_as_string(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func HmacSha256(mnemonic string, passphrase string, isMainnet bool, index uint32, derivationPath string, msg []byte) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_hmac_sha256(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterStringINSTANCE.Lower(derivationPath), FfiConverterBytesINSTANCE.Lower(msg), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func IsChainSupported(chainId uint32) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_is_chain_supported(FfiConverterUint32INSTANCE.Lower(chainId), _uniffiStatus)
	}))
}

func NewBitcoinTransactionOptions(inputAmounts []uint64, prevScripts []string) TransactionChainOptions {
	return FfiConverterTransactionChainOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_bitcoin_transaction_options(FfiConverterSequenceUint64INSTANCE.Lower(inputAmounts), FfiConverterSequenceStringINSTANCE.Lower(prevScripts), _uniffiStatus),
		}
	}))
}

func NewCosmosTransactionOptions(chainId string, accountNumber uint64) TransactionChainOptions {
	return FfiConverterTransactionChainOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_cosmos_transaction_options(FfiConverterStringINSTANCE.Lower(chainId), FfiConverterUint64INSTANCE.Lower(accountNumber), _uniffiStatus),
		}
	}))
}

func NewEthWalletOptions(useLegacyPath bool, chainId uint32) WalletOptions {
	return FfiConverterWalletOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_eth_wallet_options(FfiConverterBoolINSTANCE.Lower(useLegacyPath), FfiConverterUint32INSTANCE.Lower(chainId), _uniffiStatus),
		}
	}))
}

func NewEvmTransactionOptions(chainId uint32) TransactionChainOptions {
	return FfiConverterTransactionChainOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_evm_transaction_options(FfiConverterUint32INSTANCE.Lower(chainId), _uniffiStatus),
		}
	}))
}

func NewIcpWalletOptions(useLegacyPath bool, keyType string) WalletOptions {
	return FfiConverterWalletOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_icp_wallet_options(FfiConverterBoolINSTANCE.Lower(useLegacyPath), FfiConverterStringINSTANCE.Lower(keyType), _uniffiStatus),
		}
	}))
}

func NewSubstrateTransactionOptions(call string, era string, nonce uint32, tip uint64, blockHash string, genesisHash string, specVersion uint32, transactionVersion uint32, appId *uint32) TransactionChainOptions {
	return FfiConverterTransactionChainOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_substrate_transaction_options(FfiConverterStringINSTANCE.Lower(call), FfiConverterStringINSTANCE.Lower(era), FfiConverterUint32INSTANCE.Lower(nonce), FfiConverterUint64INSTANCE.Lower(tip), FfiConverterStringINSTANCE.Lower(blockHash), FfiConverterStringINSTANCE.Lower(genesisHash), FfiConverterUint32INSTANCE.Lower(specVersion), FfiConverterUint32INSTANCE.Lower(transactionVersion), FfiConverterOptionalUint32INSTANCE.Lower(appId), _uniffiStatus),
		}
	}))
}

func NewWalletOptions(useLegacyPath bool) WalletOptions {
	return FfiConverterWalletOptionsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_new_wallet_options(FfiConverterBoolINSTANCE.Lower(useLegacyPath), _uniffiStatus),
		}
	}))
}

func SignEcdsa(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte, derivationPath string) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_sign_ecdsa(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterBytesINSTANCE.Lower(msg), FfiConverterStringINSTANCE.Lower(derivationPath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func SignEcdsaRecoverable(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_sign_ecdsa_recoverable(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), FfiConverterBytesINSTANCE.Lower(msg), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func SignMessage(account KosAccount, hex string, legacy bool) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_sign_message(FfiConverterKosAccountINSTANCE.Lower(account), FfiConverterStringINSTANCE.Lower(hex), FfiConverterBoolINSTANCE.Lower(legacy), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func SignTransaction(account KosAccount, raw string, options *TransactionChainOptions) (KosTransaction, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[KosError](FfiConverterKosError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_sign_transaction(FfiConverterKosAccountINSTANCE.Lower(account), FfiConverterStringINSTANCE.Lower(raw), FfiConverterOptionalTransactionChainOptionsINSTANCE.Lower(options), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue KosTransaction
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterKosTransactionINSTANCE.Lift(_uniffiRV), nil
	}
}

func Slip77MasterBlindingKey(mnemonic string, passphrase string, isMainnet bool, index uint32) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[LdError](FfiConverterLdError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_kos_mobile_fn_func_slip77_master_blinding_key(FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterStringINSTANCE.Lower(passphrase), FfiConverterBoolINSTANCE.Lower(isMainnet), FfiConverterUint32INSTANCE.Lower(index), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

func ValidateMnemonic(mnemonic string) bool {
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_kos_mobile_fn_func_validate_mnemonic(FfiConverterStringINSTANCE.Lower(mnemonic), _uniffiStatus)
	}))
}
