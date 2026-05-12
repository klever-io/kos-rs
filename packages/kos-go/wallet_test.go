package kosgo

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testMnemonic     = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	walletIterations = uint32(10000)
)

func TestWalletShouldGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic(12)
	assert.Nil(t, err, "Failed to generate mnemonic")
	assert.NotEmpty(t, mnemonic, "The mnemonic should not be empty")
}

func TestWalletShouldFailToGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic(-1)
	assert.Error(t, err, "An error was expected but found a mnemonic")
	assert.Empty(t, mnemonic)
	assert.True(t, errors.Is(err, ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestWalletShouldValidateMnemonicWithSuccess(t *testing.T) {
	result := ValidateMnemonic(testMnemonic)
	assert.True(t, result, "The mnemonic should be valid")
}

func TestWalletShouldValidateMnemonicWithFailure(t *testing.T) {
	mnemonic := "abandon xxx abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	result := ValidateMnemonic(mnemonic)
	assert.False(t, result, "The mnemonic should not be valid")
}

func TestWalletShouldFailToGetAccountFromMnemonicWithInvalidChain(t *testing.T) {
	chainID := uint32(999)
	_, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Error(t, err, "An error was expected but found an account")
	assert.True(t, errors.Is(err, ErrKosErrorUnsupportedChain), "Invalid error: expected ErrKosErrorUnsupportedChain")
	assert.Contains(t, err.Error(), strconv.Itoa(int(chainID)), "Error should include the chain ID")
}

func TestWalletShouldGetAccountFromMnemonic(t *testing.T) {
	chainID := uint32(38)
	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")
	assert.Equal(t, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", account.Address, "The address doesn't match")
	assert.Equal(t, "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d", account.PrivateKey, "The private_key doesn't match")
	assert.Equal(t, chainID, account.ChainId, "The chain_id doesn't match")
}

func TestWalletShouldFailToGetAccountFromMnemonicWithInvalidMnemonic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon klv abandon abandon abandon abandon abandon about"
	_, err := GenerateWalletFromMnemonic(mnemonic, 38, 0, nil)
	assert.Error(t, err, "An error was expected but found an account")
	assert.True(t, errors.Is(err, ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestWalletShouldGetAllSupportedChainsAccountFromMnemonic(t *testing.T) {
	chains := GetSupportedChains()
	assert.NotEmpty(t, chains, "Supported chains should not be empty")

	for _, chainCode := range chains {
		account, err := GenerateWalletFromMnemonic(testMnemonic, chainCode, 0, nil)
		assert.Nil(t, err, "Unexpected error for chain %d: %v", chainCode, err)
		assert.NotEmpty(t, account.Address, "The address for chain %d is empty", chainCode)
		assert.NotEmpty(t, account.PrivateKey, "The private_key for chain %d is empty", chainCode)
		assert.Equal(t, chainCode, account.ChainId, "The chain_id doesn't match for chain %d", chainCode)
	}
}

func TestWalletShouldGetAccountFromPrivateKey(t *testing.T) {
	privateKey := "8734062c1158f26a3ca8a4a0da87b527a7c168653f7f4c77045e5cf571497d9d"
	chainID := uint32(38)
	account, err := GenerateWalletFromPrivateKey(chainID, privateKey, nil)
	assert.Nil(t, err, "Failed to generate wallet from private key")
	assert.Equal(t, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", account.Address, "The address doesn't match")
	assert.Equal(t, privateKey, account.PrivateKey, "The private_key doesn't match")
	assert.Equal(t, chainID, account.ChainId, "The chain_id doesn't match")
}

func TestWalletShouldFailToGetAccountFromPrivateKey(t *testing.T) {
	_, err := GenerateWalletFromPrivateKey(38, "", nil)
	assert.Error(t, err, "An error was expected")
	assert.True(t, errors.Is(err, ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestWalletShouldEncryptWithGcmAndDecryptData(t *testing.T) {
	password := "myPass"
	encrypted, err := EncryptWithGcm(testMnemonic, password, walletIterations)
	assert.Nil(t, err, "Failed to encrypt with GCM")
	decrypted, err := Decrypt(encrypted, password, walletIterations)
	assert.Nil(t, err, "Failed to decrypt")
	assert.Equal(t, testMnemonic, decrypted, "The data is not the same")
}

func TestWalletShouldEncryptWithCbcAndDecryptData(t *testing.T) {
	password := "myPass"
	encrypted, err := EncryptWithCbc(testMnemonic, password, walletIterations)
	assert.Nil(t, err, "Failed to encrypt with CBC")
	decrypted, err := Decrypt(encrypted, password, walletIterations)
	assert.Nil(t, err, "Failed to decrypt")
	assert.Equal(t, testMnemonic, decrypted, "The data is not the same")
}

func TestWalletShouldEncryptWithCfbAndDecryptData(t *testing.T) {
	password := "myPass"
	encrypted, err := EncryptWithCfb(testMnemonic, password, walletIterations)
	assert.Nil(t, err, "Failed to encrypt with CFB")
	decrypted, err := Decrypt(encrypted, password, walletIterations)
	assert.Nil(t, err, "Failed to decrypt")
	assert.Equal(t, testMnemonic, decrypted, "The data is not the same")
}

func TestWalletShouldFailToDecryptWithWrongPassword(t *testing.T) {
	encrypted, err := EncryptWithGcm(testMnemonic, "myPass", walletIterations)
	assert.Nil(t, err, "Failed to encrypt with GCM")
	_, err = Decrypt(encrypted, "wrong", walletIterations)
	assert.Error(t, err, "An error was expected but found decrypted data")
	assert.True(t, errors.Is(err, ErrKosErrorKosDelegate), "Invalid error: expected KosErrorKosDelegate")
}

func TestWalletShouldSignTransactionKlv(t *testing.T) {
	chainID := uint32(38)
	raw := hex.EncodeToString([]byte(`{"RawData":{"BandwidthFee":1000000,"ChainID":"MTAwNDIw","Contract":[{"Parameter":{"type_url":"type.googleapis.com/proto.TransferContract","value":"CiAysyg0Aj8xj/rr5XGU6iJ+ATI29mnRHS0W0BrC1vz0CBgK"}}],"KAppFee":500000,"Nonce":39,"Sender":"5BsyOlcf2VXgnNQWYP9EZcP0RpPIfy+upKD8QIcnyOo=","Version":1}}`))

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, chainID, transaction.ChainId, "The chain_id doesn't match")
	assert.Equal(t, "klv1usdnywjhrlv4tcyu6stxpl6yvhplg35nepljlt4y5r7yppe8er4qujlazy", transaction.Sender, "The sender doesn't match")
	assert.Equal(t, "7b2252617744617461223a7b224e6f6e6365223a33392c2253656e646572223a22354273794f6c6366325658676e4e5157595039455a6350305270504966792b75704b44385149636e794f6f3d222c22436f6e7472616374223a5b7b22506172616d65746572223a7b22747970655f75726c223a22747970652e676f6f676c65617069732e636f6d2f70726f746f2e5472616e73666572436f6e7472616374222c2276616c7565223a224369417973796730416a38786a2f72723558475536694a2b41544932396d6e52485330573042724331767a304342674b227d2c2254797065223a6e756c6c7d5d2c225065726d697373696f6e4944223a6e756c6c2c2244617461223a6e756c6c2c224b417070466565223a3530303030302c2242616e647769647468466565223a313030303030302c2256657273696f6e223a312c22436861696e4944223a224d5441774e444977222c224b4441466565223a6e756c6c7d2c225369676e6174757265223a5b2267555a444950537853713430516a54424d33382f4441417557546d37443154486f324b5756716869545943756d354f2b4f53577754596c6749553052674a36756e6767316375434a50636d59574e676a444b412f44413d3d225d2c22526573756c74223a6e756c6c2c22526573756c74436f6465223a6e756c6c2c225265636569707473223a6e756c6c2c22426c6f636b223a6e756c6c7d", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "81464320f4b14aae344234c1337f3f0c002e5939bb0f54c7a3629656a8624d80ae9b93be3925b04d8960214d11809eae9e083572e0893dc99858d8230ca03f0c", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignTransactionTrx(t *testing.T) {
	chainID := uint32(1)
	raw := "0a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e031"

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, chainID, transaction.ChainId, "The chain_id doesn't match")
	assert.Equal(t, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", transaction.Sender, "The sender doesn't match")
	assert.Equal(t, "0a83010a02487c22080608af18f6ec6c8340d8f8fae2e0315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541e825d52582eec346c839b4875376117904a76cbc12154120ab1300cf70c048e4cf5d5b1b33f59653ed6626180a708fb1f7e2e0311241e8469947140bdaff5cce4000e60a3bd95ca3de551870a450ce51ab41acfefe8b009e7ca1caaad63efdae94332f6282ef8766471236849511e70d7b1c22c15f7b01", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "e8469947140bdaff5cce4000e60a3bd95ca3de551870a450ce51ab41acfefe8b009e7ca1caaad63efdae94332f6282ef8766471236849511e70d7b1c22c15f7b01", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignTransactionIota(t *testing.T) {
	chainID := uint32(69)
	raw := "00000200080a000000000000000020f852c6b5ad76755c760c81fc629f1faa229529ab438e9a38fe414f756d21116f0202000101000001010300000000010100ae772350bb072a38c1cfae0478b686a9a1021f57f81f7d9872e80299ba9aaa02015fe88858aa27e33850dad08047297a4cb0b80ec9565ca391ba295923dc167b606f83fd140000000020da023c194b290b1f98c47a7631d0cc1081fc368bccfe238965e66d66e68c65f5ae772350bb072a38c1cfae0478b686a9a1021f57f81f7d9872e80299ba9aaa02e803000000000000307a2d000000000000"

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, chainID, transaction.ChainId, "The chain_id doesn't match")
	assert.Equal(t, "0x365b74f27ca7c6d7ce019d73042f85cc4627e1aeec2b7822994e16010234e576", transaction.Sender, "The sender doesn't match")
	assert.Equal(t, "00000200080a000000000000000020f852c6b5ad76755c760c81fc629f1faa229529ab438e9a38fe414f756d21116f0202000101000001010300000000010100ae772350bb072a38c1cfae0478b686a9a1021f57f81f7d9872e80299ba9aaa02015fe88858aa27e33850dad08047297a4cb0b80ec9565ca391ba295923dc167b606f83fd140000000020da023c194b290b1f98c47a7631d0cc1081fc368bccfe238965e66d66e68c65f5ae772350bb072a38c1cfae0478b686a9a1021f57f81f7d9872e80299ba9aaa02e803000000000000307a2d000000000000", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "0005f770aee829e547f3de76b1a5aaf762227fac4a097e638d57060108140507b65328db581bc617e500b27c39fbae85e91be92280d95b2f031259d2915183440d931c54b678837cf96a49ee1d1122027fabadf0aee97d9f9094187db8be396f63", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignTransactionSol(t *testing.T) {
	chainID := uint32(40)
	raw := "00010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000"

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "01ed844199837f89a97752816386224313026513146985748655927567a596ad04f66f504273eae87b4ec6b0166641f35f27d7b412166b2cc23d2992102b985203010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "ed844199837f89a97752816386224313026513146985748655927567a596ad04f66f504273eae87b4ec6b0166641f35f27d7b412166b2cc23d2992102b985203", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignLegacyTransactionSol(t *testing.T) {
	chainID := uint32(40)
	raw := "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010002049a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc3747b97530182dceb9d42c01c0581af062c94ecae225cfc500fdc695b85f1063a27400000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000a0daf9b9fa585f46e77f3ca63a84432074a910f08ee3b69c4316392720a457190303000502490200000300090380969800000000000202000114020000000100000000000000b2607248be872c18"

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "01b079c666c9ff53bb26d7606d10131ebbc8d398dac9fd1285d5138bbdd521758d7a6b6bdb2876730637704eb1511f3f7d842343b9e406bb3e3583d6588949a904010002049a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc3747b97530182dceb9d42c01c0581af062c94ecae225cfc500fdc695b85f1063a27400000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000a0daf9b9fa585f46e77f3ca63a84432074a910f08ee3b69c4316392720a457190303000502490200000300090380969800000000000202000114020000000100000000000000b2607248be872c18", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "b079c666c9ff53bb26d7606d10131ebbc8d398dac9fd1285d5138bbdd521758d7a6b6bdb2876730637704eb1511f3f7d842343b9e406bb3e3583d6588949a904", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignV0TransactionSol(t *testing.T) {
	chainID := uint32(40)
	raw := "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800100060a9a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc374758ef677fb5635e6473724b70e16b640554034ea47a1c7b3fcd88853c415d325476b8050abc2986a13e443af9bf4ea4d310daf4ce761c12c5ac5622ae757c36d2b19942026d00b891714c2544c4f6919b7c4116ef7246443c88b215ee7ddf6eaf0000000000000000000000000000000000000000000000000000000000000000ac1f83fdb9ce550de95d558cdc795461ccf4374ac688ec13a98400220a78da060306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000b43ffa27f5d7f64a74c09b1f295879de4b09ab36dfc9dd514b321aa7b38ce5e80479d55bf231c06eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138f06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a985e5e847a818aa8ed7e1a03d4b1dbf41ca5fe93a7317a75d56e8fbef5b3979640506000502e6be0100060009034491060000000000080503001309040993f17b64f484ae76ff08180900020308130107080f110b0002030e0a0d0c091212100523e517cb977ae3ad2a0100000019640001f82e010000000000c1ad0900000000002b000509030300000109010fe5dfa171f7e49e10a3d6a91b55bb5714a643b5e94e1e5af2fe8b34d5be4fb205e2e1e3e8c905e7e4e0e545"

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "0140098643a37209b2e0984c2f55872ccf150c44a1100a16a985b1bc04b13c31f9d9d1b070229241df5aaa21af22e0e4f88b6371106766fd95096b67f1066f8701800100060a9a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc374758ef677fb5635e6473724b70e16b640554034ea47a1c7b3fcd88853c415d325476b8050abc2986a13e443af9bf4ea4d310daf4ce761c12c5ac5622ae757c36d2b19942026d00b891714c2544c4f6919b7c4116ef7246443c88b215ee7ddf6eaf0000000000000000000000000000000000000000000000000000000000000000ac1f83fdb9ce550de95d558cdc795461ccf4374ac688ec13a98400220a78da060306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000b43ffa27f5d7f64a74c09b1f295879de4b09ab36dfc9dd514b321aa7b38ce5e80479d55bf231c06eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138f06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a985e5e847a818aa8ed7e1a03d4b1dbf41ca5fe93a7317a75d56e8fbef5b3979640506000502e6be0100060009034491060000000000080503001309040993f17b64f484ae76ff08180900020308130107080f110b0002030e0a0d0c091212100523e517cb977ae3ad2a0100000019640001f82e010000000000c1ad0900000000002b000509030300000109010fe5dfa171f7e49e10a3d6a91b55bb5714a643b5e94e1e5af2fe8b34d5be4fb205e2e1e3e8c905e7e4e0e545", transaction.Raw, "The raw doesn't match")
	assert.Equal(t, "40098643a37209b2e0984c2f55872ccf150c44a1100a16a985b1bc04b13c31f9d9d1b070229241df5aaa21af22e0e4f88b6371106766fd95096b67f1066f8701", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignTransactionCosmos(t *testing.T) {
	chainID := uint32(48)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := NewCosmosTransactionOptions("celestia", 274454)
	transaction, err := SignTransaction(account, "0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c06", options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c061a409c611838f8614c3f9bbbda156d39f4219b8cbb181b0e34466d1e9daf05f5973c2f302f60d49333a0e12956021d51ce048b475765e6b46ba3c678594b1b7513f7", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionBch(t *testing.T) {
	chainID := uint32(18)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	prevScript, _ := hex.DecodeString("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac")
	options := TransactionChainOptionsBtc{
		PrevScripts:  [][]byte{prevScript, prevScript},
		InputAmounts: []uint64{498870, 1001016},
	}
	transaction, err := SignTransaction(account, "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000", &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d010000006b48304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c010000006a4730440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionBtc(t *testing.T) {
	chainID := uint32(2)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	prevScript, _ := hex.DecodeString("0014546d5f8e86641e4d1eec5b9155a540d953245e4a")
	options := TransactionChainOptionsBtc{
		PrevScripts:  [][]byte{prevScript, prevScript},
		InputAmounts: []uint64{5000, 10000},
	}
	transaction, err := SignTransaction(account, "0100000002badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a00000000", &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "01000000000102badfa0606bc6a1738d8ddf951b1ebf9e87779934a5774b836668efb5a6d643970000000000fffffffffe60fbeb66791b10c765a207c900a08b2a9bd7ef21e1dd6e5b2ef1e9d686e5230000000000ffffffff028813000000000000160014e4132ab9175345e24b344f50e6d6764a651a89e6c21f000000000000160014546d5f8e86641e4d1eec5b9155a540d953245e4a02483045022100ca1df8381e56e2ac2228e040cc2ff1c1079928222365f5c62cd6c18f398a6f55022029dca1177ab6edcfa03a25c7df32e1644c5d1fe496c6c7995a715373b56a591901210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c024830450221009496122a56551a0dab4fa8562474c943c79158f7592a845abd7b60ddf34c10c902205021b73e27a44b0c365fbd015133a4bb6dce79dd09705096de1c7b31a1f9b8a701210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c00000000", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionDash(t *testing.T) {
	chainID := uint32(11)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	prevScript, _ := hex.DecodeString("76a914be4232b46086c1d46d12c65eacbd807e87b92a5488ac")
	options := TransactionChainOptionsBtc{
		PrevScripts:  [][]byte{prevScript},
		InputAmounts: []uint64{1013578},
	}
	transaction, err := SignTransaction(account, "0100000001c2c12c2f80249f568cf90ffd87d47afbbed81e803d2a7076c554e81b73253ab50000000000ffffffff02e8030000000000001976a914a3d92f1bab64bb8154ed118cd27fb5081344ca8488ac04580f00000000001976a914be4232b46086c1d46d12c65eacbd807e87b92a5488ac00000000", &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "0100000001c2c12c2f80249f568cf90ffd87d47afbbed81e803d2a7076c554e81b73253ab5000000006a4730440220423d61c364084d0c24f155519d4991549b1090bdd65ac6c74ebc6f3917d5dff6022056c3af1de9b4e33369dcd134591a80554ce5a108c300bc0cc2ed4c11d0a6861c0121026fa9a6f213b6ba86447965f6b4821264aaadd7521f049f00db9c43a770ea7405ffffffff02e8030000000000001976a914a3d92f1bab64bb8154ed118cd27fb5081344ca8488ac04580f00000000001976a914be4232b46086c1d46d12c65eacbd807e87b92a5488ac00000000", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionDoge(t *testing.T) {
	chainID := uint32(12)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	prevScript, _ := hex.DecodeString("76a91479975a24fdab613e17cf184bc185071aad17441888ac")
	options := TransactionChainOptionsBtc{
		PrevScripts:  [][]byte{prevScript},
		InputAmounts: []uint64{63609889529},
	}
	transaction, err := SignTransaction(account, "0100000001c4d32b8d271b3d4c7c269f2af31f87ad71315b72610744843bca92600c6c662d0300000000feffffff01f98b1acc0e0000001976a9146dc8f8d77f0d1ea8c42f2374e5b3abbb77fda44f88ac00000000", &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "0100000001c4d32b8d271b3d4c7c269f2af31f87ad71315b72610744843bca92600c6c662d030000006a4730440220198e150a394004850b0ab50423ab583e7b4a7fdb12f6ff98849ed532a8b8f5fc02202cfea08c49254a1b245cf9f460d596812e0f4dd0d1ddb1f008fe01d52f3d74f7012102cc6b0dc33aabcf3a23643e5e2919a80c50fb3dd2129ce409bbc5f0d4643d05e0feffffff01f98b1acc0e0000001976a9146dc8f8d77f0d1ea8c42f2374e5b3abbb77fda44f88ac00000000", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionEth(t *testing.T) {
	chainID := uint32(3)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := NewEvmTransactionOptions(1)
	transaction, err := SignTransaction(account, "b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080", options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "02f8b30182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac001a0ac17a21525645e7bdf653b2e46b4fb7b33668b0cb42ce38bf8fbb752e527fb63a0e56f5ff3e3eb15441eeaf144237204b0435ed31d0e009153512074fa56b2cc62", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionEthBasedLegacy(t *testing.T) {
	chainID := uint32(3)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := NewEvmTransactionOptions(43114)
	transaction, err := SignTransaction(account, "ea13840afab0ab82520894f1eea5c58414264171cf40592c3468adb6af1b3387038d7ea4c6800080808080", options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "f86a13840afab0ab82520894f1eea5c58414264171cf40592c3468adb6af1b3387038d7ea4c68000801ca0735e6e6f62302109f60750189a1c3e8d16990beb5e3036963c9e069d6e0c39c3a075ab2a97863ec9e3be9cae77637af453fb94bea06c67d637e79d98ec77b74e4e", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignTransactionDot(t *testing.T) {
	chainID := uint32(21)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	call, _ := hex.DecodeString("0a0300b8c8ac77e723fae060f2dc70d00a591e1127ec07e0e81e2237a823cbe5210d1e02286bee")
	era, _ := hex.DecodeString("0501")
	assetId := "0"
	blockHash, _ := hex.DecodeString("781cf57533b15a5a13729a33543fd6ae137bce54ef14eb933b0a4813489e7e0a")
	genesisHash, _ := hex.DecodeString("68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f")
	options := TransactionChainOptionsSubstrate{
		Call:               call,
		Era:                era,
		Nonce:              6,
		Tip:                0,
		AssetId:            &assetId,
		BlockHash:          blockHash,
		GenesisHash:        genesisHash,
		SpecVersion:        2000002,
		TransactionVersion: 15,
		AppId:              nil,
		SignedExtensions:   nil,
	}
	transaction, err := SignTransaction(account, "0a0300b8c8ac77e723fae060f2dc70d00a591e1127ec07e0e81e2237a823cbe5210d1e02286bee05011800000082841e000f00000068d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f781cf57533b15a5a13729a33543fd6ae137bce54ef14eb933b0a4813489e7e0a00", &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, 290, len(transaction.Raw), "The raw length doesn't match")
}

func TestWalletShouldSignTransactionIcp(t *testing.T) {
	chainID := uint32(31)

	walletOptions := NewIcpWalletOptions(false, "ed25519")
	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, &walletOptions)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := SignTransaction(account, "35623232333036313336333933363333333236343337333233363335333733313337333533363335333733333337333433353332333133373635333533363336333433393636363633323331333233383333333636363330363133323332333633323336333736363333333036333631333033303635333836353334363633323635333833333334363236313336363333303634333236343338333233343332333733323336333933303337333033303232326332323330363133363339333633333332363433373332333633353337333133373335333633353337333333373334333136323331333433303632363236343337333633353337333136333330363133333334333333333331333333313338333533343333333736323635333836323338363236333334363433353635333233383339333833303331363136353631333133373635363133303336363136363332333036343331363533393337333532323564", nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "5b226366623365373264373431353231613830336136613337363938363434313365656639353030646662356662343838643638623834303636663836343337383561363964613833653265633463393336653834303832373261643936643164343631643466393161323664643966623433643231663931333061373562393036222c223937636130633265656635363733656530353238623361666134363863666432626433333834623164643938643365346339313731383535626564386239313563386239373161623861383432623566623866633738666462376361383139373533663335353232396431666330643537633337303965303631356330353034225d", transaction.Signature, "The signature doesn't match")
}

func TestWalletShouldSignTransactionXlm(t *testing.T) {
	chainID := uint32(6)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	rawBytes, _ := base64.StdEncoding.DecodeString("AAAAAgAAAACn54ed9JVAQdXN6d0E5Q+QH/0BOFi5/jWw3LII81gdPgAAAGQDcl2eAAAAGQAAAAEAAAAAAAAAAAAAAABobmAtAAAAAAAAAAEAAAAAAAAAAQAAAAAvdBR3bp6jt7IkpRzKY3SZsapC3gFKYPBm3sN2Ss3C7QAAAAAAAAAAAAAAAQAAAAAAAAAA")
	transaction, err := SignTransaction(account, hex.EncodeToString(rawBytes), nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "41414141416741414141436e35346564394a56415164584e3664304535512b51482f30424f4669352f6a5777334c4949383167645067414141475144636c32654141414147514141414145414141414141414141414141414141426f626d417441414141414141414141454141414141414141414151414141414176644252336270366a7437496b70527a4b5933535a736170433367464b5950426d33734e325373334337514141414141414141414141414141415141414141414141414142334b70434f4141414145434d504b75416c5443333463325471557a6f305a665870314e74524c574e7434343857797a724c72515848536948696d75574334654c306b74616b54485231574e6c6a5a47687775756f594a7938677062442b473848", transaction.Raw, "The Raw doesn't match")
}

func TestWalletShouldSignTransactionWithOptions(t *testing.T) {
	chainID := uint32(61)

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := NewEvmTransactionOptions(88888)
	transaction, err := SignTransaction(account, "b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080", options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t, "02f87101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c001a044c69f41bf47ad50dc98c74af68811384c9172055b01fcaa39e70f53df69b632a05e071cf1f9e12500b525f03a29f567520e1ea49a97e6a29d1fd432dc6303353e", transaction.Raw, "The raw doesn't match")
}

func TestWalletShouldSignMessage(t *testing.T) {
	chainID := uint32(38)
	message := hex.EncodeToString([]byte("Hello World"))

	account, err := GenerateWalletFromMnemonic(testMnemonic, chainID, 0, nil)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	signature, err := SignMessage(account, message, true)
	assert.Nil(t, err, "Failed to sign message")
	assert.Equal(t, 64, len(signature), "The signature length doesn't match")
}

func TestWalletShouldReturnTrueForSupportedChain(t *testing.T) {
	result := IsChainSupported(38)
	assert.True(t, result, "The chain should be supported")
}

func TestWalletShouldReturnFalseForUnsupportedChain(t *testing.T) {
	result := IsChainSupported(999)
	assert.False(t, result, "The chain should not be supported")
}

func TestWalletShouldGetSupportedChains(t *testing.T) {
	chains := GetSupportedChains()
	assert.NotEmpty(t, chains, "The supported chains should not be empty")
}

func TestWalletShouldGetPathByChain(t *testing.T) {
	path, err := GetPathByChain(38, 0, false)
	assert.Nil(t, err, "Failed to get path for chain 38")
	assert.Equal(t, "m/44'/690'/0'/0'/0'", path)

	path, err = GetPathByChain(27, 0, false)
	assert.Nil(t, err, "Failed to get path for chain 27")
	assert.Equal(t, "", path)

	path, err = GetPathByChain(27, 1, false)
	assert.Nil(t, err, "Failed to get path for chain 27 index 1")
	assert.Equal(t, "//0///", path)
}
