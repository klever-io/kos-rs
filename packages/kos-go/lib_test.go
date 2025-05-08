package kosgo

import (
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
	"github.com/stretchr/testify/assert"
)

func TestShouldGenerateMnemonic(t *testing.T) {
	size := int32(12)
	mnemonic, err := kos_mobile.GenerateMnemonic(size)
	assert.Nil(t, err, "Failed to generate mnemonic")
	assert.NotEmpty(t, mnemonic, "The mnemonic should not be empty")
}

func TestShouldFailToGenerateMnemonic(t *testing.T) {
	size := int32(-1)
	mnemonic, err := kos_mobile.GenerateMnemonic(size)
	assert.Error(t, err, "A error was expected but found a mnemonic")
	assert.Empty(t, mnemonic)
	assert.True(t, errors.Is(err, kos_mobile.ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestShouldValidateMnemonicWithSuccess(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	result := kos_mobile.ValidateMnemonic(mnemonic)
	assert.True(t, result, "The mnemonic should be valid")
}

func TestShouldValidateMnemonicWithFailure(t *testing.T) {
	mnemonic := "abandon xxx abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	result := kos_mobile.ValidateMnemonic(mnemonic)
	assert.False(t, result, "The mnemonic should not be valid")
}

func TestShouldFailToGetAccountFromMnemonicWithInvalidChain(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	index := uint32(0)
	chainID := uint32(999)

	wallet, err := kos_mobile.GenerateWalletFromMnemonic(mnemonic, chainID, index, false)

	assert.Error(t, err, "An error was expected but found a mnemonic")
	assert.Empty(t, wallet)

	assert.Contains(t, err.Error(), "UnsupportedChain", "Error should indicate an unsupported chain")
	assert.Contains(t, err.Error(), strconv.Itoa(int(chainID)), "Error should include the chain ID")
}

func TestShouldGetAccountFromMnemonic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	index := uint32(0)
	chainID := uint32(38)

	account, err := kos_mobile.GenerateWalletFromMnemonic(mnemonic, chainID, index, false)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")
	assert.Equal(t, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", account.Address, "The address doesn't match")
	assert.Equal(t, "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d", account.PrivateKey, "The private_key doesn't match")
	assert.Equal(t, chainID, account.ChainId, "The chain_id doesn't match")
}

func TestShouldFailToGetAccountFromMnemonicWithInvalidMnemonic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon klv abandon abandon abandon abandon abandon about"
	index := uint32(0)
	chainID := uint32(38)

	account, err := kos_mobile.GenerateWalletFromMnemonic(mnemonic, chainID, index, false)

	assert.Error(t, err, "An error was expected but found an account")
	assert.Empty(t, account, "Account should be empty when there's an error")
	assert.True(t, errors.Is(err, kos_mobile.ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestShouldFailToGetAccountFromPrivateKey(t *testing.T) {
	privateKey := ""
	chainID := uint32(38)

	account, err := kos_mobile.GenerateWalletFromPrivateKey(chainID, privateKey)
	assert.Error(t, err, "An error was expected but found a pk %s", account.PrivateKey)
	assert.True(t, errors.Is(err, kos_mobile.ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestShouldEncryptWithGmcAndDecryptData(t *testing.T) {
	originalData := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := "myPass"

	encryptedData, err := kos_mobile.EncryptWithGmc(originalData, password)
	assert.Nil(t, err, "Failed to encrypt data with GMC")

	decryptedData, err := kos_mobile.Decrypt(encryptedData, password)
	assert.Nil(t, err, "Failed to decrypt data")
	assert.Equal(t, originalData, decryptedData, "The data is not the same")
}

func TestShouldEncryptWithCbcAndDecryptData(t *testing.T) {
	originalData := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := "myPass"

	encryptedData, err := kos_mobile.EncryptWithCbc(originalData, password)
	assert.Nil(t, err, "Failed to encrypt data with CBC")

	decryptedData, err := kos_mobile.Decrypt(encryptedData, password)
	assert.Nil(t, err, "Failed to decrypt data")
	assert.Equal(t, originalData, decryptedData, "The data is not the same")
}

func TestShouldEncryptWithCbfAndDecryptData(t *testing.T) {
	originalData := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := "myPass"

	encryptedData, err := kos_mobile.EncryptWithCfb(originalData, password)
	assert.Nil(t, err, "Failed to encrypt data with CFB")

	decryptedData, err := kos_mobile.Decrypt(encryptedData, password)
	assert.Nil(t, err, "Failed to decrypt data")
	assert.Equal(t, originalData, decryptedData, "The data is not the same")
}

func TestShouldFailToDecryptWithWrongPassword(t *testing.T) {
	originalData := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := "myPass"

	encryptedData, err := kos_mobile.EncryptWithGmc(originalData, password)
	assert.Nil(t, err, "Failed to encrypt data with GMC")

	decryptedData, err := kos_mobile.Decrypt(encryptedData, "wrong")
	assert.Error(t, err, "An error was expected but found decrypted data")
	assert.Empty(t, decryptedData)
	assert.True(t, errors.Is(err, kos_mobile.ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestShouldSignRawTransactionKlv(t *testing.T) {
	chainID := uint32(38)
	raw := hex.EncodeToString([]byte(`{"RawData":{"BandwidthFee":1000000,"ChainID":"MTAwNDIw","Contract":[{"Parameter":{"type_url":"type.googleapis.com/proto.TransferContract","value":"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK"}}],"KAppFee":500000,"Nonce":39,"Sender":"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=","Version":1}}`))

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, chainID, transaction.ChainId, "The chain_id doesn't match")
	assert.Equal(t, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", transaction.Sender, "The sender doesn't match")
	assert.Equal(t, "7b22426c6f636b223a6e756c6c2c2252617744617461223a7b2242616e647769647468466565223a313030303030302c22436861696e4944223a224d5441774e444977222c22436f6e7472616374223a5b7b22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6e7472616374222c2276616c7565223a224369417973796730416a38786a2f72723558475536694a2b41544932396d6e52485330573042724331767a304342674b227d2c2254797065223a6e756c6c7d5d2c2244617461223a6e756c6c2c224b417070466565223a3530303030302c224b4441466565223a6e756c6c2c224e6f6e6365223a33392c225065726d697373696f6e4944223a6e756c6c2c2253656e646572223a22354273794f6c6366325658676e4e5157595039455a6350305270504966792b75704b44385149636e794f6f3d222c2256657273696f6e223a317d2c225265636569707473223a6e756c6c2c22526573756c74223a6e756c6c2c22526573756c74436f6465223a6e756c6c2c225369676e6174757265223a5b2267555a444950537853713430516a54424d33382f4441417557546d37443154486f324b5756716869545943756d354f2b4f53577754596c6749553052674a36756e6767316375434a50636d59574e676a444b412f44413d3d225d7d", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "81464320f4b14aae344234c1337f3f0c002e5939bb0f54c7a3629656a8624d80ae9b93be3925b04d8960214d11809eae9e083572e0893dc99858d8230ca03f0c", transaction.Signature, "The signature doesn't match")
}

func TestShouldSignRawTransactionTrx(t *testing.T) {
	chainID := uint32(1)
	raw := "0a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031"

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, chainID, transaction.ChainId, "The chain_id doesn't match")
	assert.Equal(t, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", transaction.Sender, "The sender doesn't match")
	assert.Equal(t, "0a83010a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e0311241e8469947140bdaff5cce4000e60a3bd95ca3de551870a450ce51ab41acfefe8b009e7ca1caaad63efdae94332f6282ef8766471236849511e70d7b1c22c15f7b01", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "e8469947140bdaff5cce4000e60a3bd95ca3de551870a450ce51ab41acfefe8b009e7ca1caaad63efdae94332f6282ef8766471236849511e70d7b1c22c15f7b01", transaction.Signature, "The signature doesn't match")
}

func TestShouldSignMessage(t *testing.T) {
	chainID := uint32(38)
	message := hex.EncodeToString([]byte("Hello World"))

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	signature, err := kos_mobile.SignMessage(account, message, true)
	assert.Nil(t, err, "Failed to sign message")
	assert.Equal(t, 64, len(signature), "The signature length doesn't match")
}

func TestShouldReturnTrueForSupportedChain(t *testing.T) {
	chainID := uint32(38)
	result := kos_mobile.IsChainSupported(chainID)
	assert.True(t, result, "The chain should be supported")
}

func TestShouldReturnFalseForUnsupportedChain(t *testing.T) {
	chainID := uint32(999)
	result := kos_mobile.IsChainSupported(chainID)
	assert.False(t, result, "The chain should not be supported")
}

func TestShouldGetSupportedChains(t *testing.T) {
	supportedChains := kos_mobile.GetSupportedChains()
	assert.NotEmpty(t, supportedChains, "The supported chains should not be empty")
}

func TestShouldGetPathByChain(t *testing.T) {
	path, err := kos_mobile.GetPathByChain(38, 0, false)
	assert.Nil(t, err, "Failed to get path for chain")
	assert.Equal(t, "m/44'/690'/0'/0'/0'", path)

	path, err = kos_mobile.GetPathByChain(27, 0, false)
	assert.Nil(t, err, "Failed to get path for chain")
	assert.Equal(t, "", path)

	path, err = kos_mobile.GetPathByChain(27, 1, false)
	assert.Nil(t, err, "Failed to get path for chain")
	assert.Equal(t, "//0///", path)
}
