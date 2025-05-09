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

func TestShouldSignRawTransactionSol(t *testing.T) {
	chainID := uint32(40)

	raw := "00010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000"

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"01ed844199837f89a97752816386224313026513146985748655927567a596ad04f66f504273eae87b4ec6b0166641f35f27d7b412166b2cc23d2992102b985203010000030101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303032a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a01020200010c020000006400000000000000",
		transaction.Raw,
		"The raw doesn't match",
	)
	assert.Equal(t,
		"ed844199837f89a97752816386224313026513146985748655927567a596ad04f66f504273eae87b4ec6b0166641f35f27d7b412166b2cc23d2992102b985203",
		transaction.Signature,
		"The signature doesn't match",
	)
}

func TestShouldSignRawLegacyTransactionSol(t *testing.T) {
	chainID := uint32(40)

	raw := "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010002049a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc3747b97530182dceb9d42c01c0581af062c94ecae225cfc500fdc695b85f1063a27400000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000a0daf9b9fa585f46e77f3ca63a84432074a910f08ee3b69c4316392720a457190303000502490200000300090380969800000000000202000114020000000100000000000000b2607248be872c18"

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"01b079c666c9ff53bb26d7606d10131ebbc8d398dac9fd1285d5138bbdd521758d7a6b6bdb2876730637704eb1511f3f7d842343b9e406bb3e3583d6588949a904010002049a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc3747b97530182dceb9d42c01c0581af062c94ecae225cfc500fdc695b85f1063a27400000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000a0daf9b9fa585f46e77f3ca63a84432074a910f08ee3b69c4316392720a457190303000502490200000300090380969800000000000202000114020000000100000000000000b2607248be872c18",
		transaction.Raw,
		"The raw doesn't match",
	)
	assert.Equal(t,
		"b079c666c9ff53bb26d7606d10131ebbc8d398dac9fd1285d5138bbdd521758d7a6b6bdb2876730637704eb1511f3f7d842343b9e406bb3e3583d6588949a904",
		transaction.Signature,
		"The signature doesn't match",
	)
}

func TestShouldSignRawV0TransactionSol(t *testing.T) {
	chainID := uint32(40)

	raw := "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800100060a9a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc374758ef677fb5635e6473724b70e16b640554034ea47a1c7b3fcd88853c415d325476b8050abc2986a13e443af9bf4ea4d310daf4ce761c12c5ac5622ae757c36d2b19942026d00b891714c2544c4f6919b7c4116ef7246443c88b215ee7ddf6eaf0000000000000000000000000000000000000000000000000000000000000000ac1f83fdb9ce550de95d558cdc795461ccf4374ac688ec13a98400220a78da060306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000b43ffa27f5d7f64a74c09b1f295879de4b09ab36dfc9dd514b321aa7b38ce5e80479d55bf231c06eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138f06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a985e5e847a818aa8ed7e1a03d4b1dbf41ca5fe93a7317a75d56e8fbef5b3979640506000502e6be0100060009034491060000000000080503001309040993f17b64f484ae76ff08180900020308130107080f110b0002030e0a0d0c091212100523e517cb977ae3ad2a0100000019640001f82e010000000000c1ad0900000000002b000509030300000109010fe5dfa171f7e49e10a3d6a91b55bb5714a643b5e94e1e5af2fe8b34d5be4fb205e2e1e3e8c905e7e4e0e545"

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(account, raw, nil)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"0140098643a37209b2e0984c2f55872ccf150c44a1100a16a985b1bc04b13c31f9d9d1b070229241df5aaa21af22e0e4f88b6371106766fd95096b67f1066f8701800100060a9a3c6870aeb9068f2bf9eddc8fb19b3d579da42c31f83099279ed3c377cc374758ef677fb5635e6473724b70e16b640554034ea47a1c7b3fcd88853c415d325476b8050abc2986a13e443af9bf4ea4d310daf4ce761c12c5ac5622ae757c36d2b19942026d00b891714c2544c4f6919b7c4116ef7246443c88b215ee7ddf6eaf0000000000000000000000000000000000000000000000000000000000000000ac1f83fdb9ce550de95d558cdc795461ccf4374ac688ec13a98400220a78da060306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000b43ffa27f5d7f64a74c09b1f295879de4b09ab36dfc9dd514b321aa7b38ce5e80479d55bf231c06eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138f06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a985e5e847a818aa8ed7e1a03d4b1dbf41ca5fe93a7317a75d56e8fbef5b3979640506000502e6be0100060009034491060000000000080503001309040993f17b64f484ae76ff08180900020308130107080f110b0002030e0a0d0c091212100523e517cb977ae3ad2a0100000019640001f82e010000000000c1ad0900000000002b000509030300000109010fe5dfa171f7e49e10a3d6a91b55bb5714a643b5e94e1e5af2fe8b34d5be4fb205e2e1e3e8c905e7e4e0e545",
		transaction.Raw,
		"The raw doesn't match",
	)
	assert.Equal(t,
		"40098643a37209b2e0984c2f55872ccf150c44a1100a16a985b1bc04b13c31f9d9d1b070229241df5aaa21af22e0e4f88b6371106766fd95096b67f1066f8701",
		transaction.Signature,
		"The signature doesn't match",
	)
}

func TestShouldSignRawTransactionCosmos(t *testing.T) {
	chainID := uint32(48)

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := kos_mobile.NewCosmosTransactionOptions("celestia", 274454)

	transaction, err := kos_mobile.SignTransaction(
		account,
		"0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c06",
		&options,
	)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c061a409c611838f8614c3f9bbbda156d39f4219b8cbb181b0e34466d1e9daf05f5973c2f302f60d49333a0e12956021d51ce048b475765e6b46ba3c678594b1b7513f7",
		transaction.Raw,
		"The raw doesn't match",
	)
}

func TestShouldSignRawTransactionEth(t *testing.T) {
	chainID := uint32(3)

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := kos_mobile.NewEvmTransactionOptions(1)

	transaction, err := kos_mobile.SignTransaction(
		account,
		"b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080",
		&options,
	)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"b87602f8730182014f84147b7eeb85084ec9f83f8301450994dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004cbeee256240c92a9ad920ea6f4d7df6466d2cdc000000000000000000000000000000000000000000000000000000000000000ac0808080",
		transaction.Raw,
		"The raw doesn't match",
	)
}

func TestShouldSignRawTransactionIcp(t *testing.T) {
	chainID := uint32(31)

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	transaction, err := kos_mobile.SignTransaction(
		account,
		"35623232333036313336333933363333333236343337333233363335333733313337333533363335333733333337333433353332333133373635333533363336333433393636363633323331333233383333333636363330363133323332333633323336333736363333333036333631333033303635333836353334363633323635333833333334363236313336363333303634333236343338333233343332333733323336333933303337333033303232326332323330363133363339333633333332363433373332333633353337333133373335333633353337333333373334333136323331333433303632363236343337333633353337333136333330363133333334333333333331333333313338333533343333333736323635333836323338363236333334363433353635333233383339333833303331363136353631333133373635363133303336363136363332333036343331363533393337333532323564",
		nil,
	)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"5b226366623365373264373431353231613830336136613337363938363434313365656639353030646662356662343838643638623834303636663836343337383561363964613833653265633463393336653834303832373261643936643164343631643466393161323664643966623433643231663931333061373562393036222c223937636130633265656635363733656530353238623361666134363863666432626433333834623164643938643365346339313731383535626564386239313563386239373161623861383432623566623866633738666462376361383139373533663335353232396431666330643537633337303965303631356330353034225d",
		transaction.Signature,
		"The signature doesn't match",
	)
}

func TestShouldSignTransactionWithOptions(t *testing.T) {
	chainID := uint32(61)
	raw := "b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080"

	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		false,
	)
	assert.Nil(t, err, "Failed to generate wallet from mnemonic")

	options := kos_mobile.NewEvmTransactionOptions(88888)
	transaction, err := kos_mobile.SignTransaction(account, raw, &options)
	assert.Nil(t, err, "Failed to sign transaction")

	assert.Equal(t,
		"b302f101819e84ae7937b285035f6cccc58252089498de4c83810b87f0e2cd92d80c9fac28c4ded4818568c696991f80c0808080",
		transaction.Raw,
		"The raw doesn't match",
	)
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
