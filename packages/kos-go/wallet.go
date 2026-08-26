package kosgo

import (
	"fmt"

	kos_mobile "github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
)

type KosAccount = kos_mobile.KosAccount
type KosTransaction = kos_mobile.KosTransaction
type KosError = kos_mobile.KosError
type KosErrorUnsupportedChain = kos_mobile.KosErrorUnsupportedChain
type KosErrorKosDelegate = kos_mobile.KosErrorKosDelegate
type KosErrorHexDecode = kos_mobile.KosErrorHexDecode
type KosErrorKosNumber = kos_mobile.KosErrorKosNumber

var ErrKosErrorUnsupportedChain = kos_mobile.ErrKosErrorUnsupportedChain
var ErrKosErrorKosDelegate = kos_mobile.ErrKosErrorKosDelegate
var ErrKosErrorHexDecode = kos_mobile.ErrKosErrorHexDecode
var ErrKosErrorKosNumber = kos_mobile.ErrKosErrorKosNumber

func GenerateMnemonic(size int32) (string, error) {
	return kos_mobile.GenerateMnemonic(size)
}

func ValidateMnemonic(mnemonic string) bool {
	return kos_mobile.ValidateMnemonic(mnemonic)
}

func GetPathByChain(chainId uint32, index uint32, useLegacyPath bool) (string, error) {
	return kos_mobile.GetPathByChain(chainId, index, useLegacyPath)
}

func GenerateWalletFromMnemonic(mnemonic string, chainId uint32, index uint32, options *WalletOptions) (KosAccount, error) {
	return kos_mobile.GenerateWalletFromMnemonic(mnemonic, chainId, index, options)
}

func GenerateWalletFromPrivateKey(chainId uint32, privateKey string, options *WalletOptions) (KosAccount, error) {
	return kos_mobile.GenerateWalletFromPrivateKey(chainId, privateKey, options)
}

func EncryptWithGcm(data string, password string, iterations uint32) (string, error) {
	return kos_mobile.EncryptWithGcm(data, password, iterations)
}

func EncryptWithCbc(data string, password string, iterations uint32) (string, error) {
	return kos_mobile.EncryptWithCbc(data, password, iterations)
}

func EncryptWithCfb(data string, password string, iterations uint32) (string, error) {
	return kos_mobile.EncryptWithCfb(data, password, iterations)
}

func Decrypt(data string, password string, iterations uint32) (string, error) {
	return kos_mobile.Decrypt(data, password, iterations)
}

// SignTransaction accepts a TransactionChainOptions interface value or a pointer to any
// concrete options struct. Pointer types are dereferenced before forwarding to kos_mobile,
// whose FFI type switch requires value types (not pointer types).
func SignTransaction(account KosAccount, raw string, options TransactionChainOptions) (KosTransaction, error) {
	if options == nil {
		return kos_mobile.SignTransaction(account, raw, nil)
	}
	var actualOpts TransactionChainOptions
	switch v := options.(type) {
	case *TransactionChainOptionsBtc:
		if v == nil {
			return KosTransaction{}, fmt.Errorf("SignTransaction: nil *TransactionChainOptionsBtc")
		}
		actualOpts = *v
	case *TransactionChainOptionsSubstrate:
		if v == nil {
			return KosTransaction{}, fmt.Errorf("SignTransaction: nil *TransactionChainOptionsSubstrate")
		}
		actualOpts = *v
	case *TransactionChainOptionsEvm:
		if v == nil {
			return KosTransaction{}, fmt.Errorf("SignTransaction: nil *TransactionChainOptionsEvm")
		}
		actualOpts = *v
	case *TransactionChainOptionsCosmos:
		if v == nil {
			return KosTransaction{}, fmt.Errorf("SignTransaction: nil *TransactionChainOptionsCosmos")
		}
		actualOpts = *v
	default:
		actualOpts = options
	}
	return kos_mobile.SignTransaction(account, raw, &actualOpts)
}

func SignMessage(account KosAccount, hex string, legacy bool) ([]byte, error) {
	return kos_mobile.SignMessage(account, hex, legacy)
}

func IsChainSupported(chainId uint32) bool {
	return kos_mobile.IsChainSupported(chainId)
}

func GetSupportedChains() []uint32 {
	return kos_mobile.GetSupportedChains()
}
