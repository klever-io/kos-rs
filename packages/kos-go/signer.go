package kosgo

import kos_mobile "github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"

type LdError = kos_mobile.LdError
type LdErrorMnemonicError = kos_mobile.LdErrorMnemonicError
type LdErrorInstanceError = kos_mobile.LdErrorIntanceError
type LdErrorSignerError = kos_mobile.LdErrorSignerError
type LdErrorGeneric = kos_mobile.LdErrorGeneric
type LdErrorDerivationError = kos_mobile.LdErrorDerivationError
type LdErrorInvalidIndex = kos_mobile.LdErrorInvalidIndex

func GenerateXpub(mnemonic string, passphrase string, isMainnet bool, index uint32) ([]byte, error) {
	return kos_mobile.GenerateXpub(mnemonic, passphrase, isMainnet, index)
}

func GetXpubAsString(mnemonic string, passphrase string, isMainnet bool, index uint32) (string, error) {
	return kos_mobile.GetXpubAsString(mnemonic, passphrase, isMainnet, index)
}

func DeriveXpub(mnemonic string, passphrase string, isMainnet bool, index uint32, derivationPath string) ([]byte, error) {
	return kos_mobile.DeriveXpub(mnemonic, passphrase, isMainnet, index, derivationPath)
}

func Slip77MasterBlindingKey(mnemonic string, passphrase string, isMainnet bool, index uint32) ([]byte, error) {
	return kos_mobile.Slip77MasterBlindingKey(mnemonic, passphrase, isMainnet, index)
}

func SignEcdsaRecoverable(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	return kos_mobile.SignEcdsaRecoverable(mnemonic, passphrase, isMainnet, index, msg)
}

func HmacSha256(mnemonic string, passphrase string, isMainnet bool, index uint32, derivationPath string, msg []byte) ([]byte, error) {
	return kos_mobile.HmacSha256(mnemonic, passphrase, isMainnet, index, derivationPath, msg)
}

func EciesEncrypt(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	return kos_mobile.EciesEncrypt(mnemonic, passphrase, isMainnet, index, msg)
}

func EciesDecrypt(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte) ([]byte, error) {
	return kos_mobile.EciesDecrypt(mnemonic, passphrase, isMainnet, index, msg)
}

func SignEcdsa(mnemonic string, passphrase string, isMainnet bool, index uint32, msg []byte, derivationPath string) ([]byte, error) {
	return kos_mobile.SignEcdsa(mnemonic, passphrase, isMainnet, index, msg, derivationPath)
}
