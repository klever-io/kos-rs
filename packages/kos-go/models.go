package kosgo

import kos_mobile "github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"

type TransactionChainOptions = kos_mobile.TransactionChainOptions
type TransactionChainOptionsEvm = kos_mobile.TransactionChainOptionsEvm
type TransactionChainOptionsBtc = kos_mobile.TransactionChainOptionsBtc
type TransactionChainOptionsSubstrate = kos_mobile.TransactionChainOptionsSubstrate
type TransactionChainOptionsCosmos = kos_mobile.TransactionChainOptionsCosmos

type WalletChainOptions = kos_mobile.WalletChainOptions
type WalletChainOptionsCustomEth = kos_mobile.WalletChainOptionsCustomEth
type WalletChainOptionsCustomIcp = kos_mobile.WalletChainOptionsCustomIcp

type WalletOptions = kos_mobile.WalletOptions

func NewSubstrateTransactionOptions(
	call string,
	era string,
	nonce uint32,
	tip uint64,
	assetId *string,
	blockHash string,
	genesisHash string,
	specVersion uint32,
	transactionVersion uint32,
	appId *uint32,
	signedExtensions *[]string,
) TransactionChainOptions {
	return kos_mobile.NewSubstrateTransactionOptions(
		call, era, nonce, tip, assetId,
		blockHash, genesisHash,
		specVersion, transactionVersion,
		appId, signedExtensions,
	)
}

func NewBitcoinTransactionOptions(inputAmounts []uint64, prevScripts []string) TransactionChainOptions {
	return kos_mobile.NewBitcoinTransactionOptions(inputAmounts, prevScripts)
}

func NewEvmTransactionOptions(chainId uint32) TransactionChainOptions {
	return kos_mobile.NewEvmTransactionOptions(chainId)
}

func NewCosmosTransactionOptions(chainId string, accountNumber uint64) TransactionChainOptions {
	return kos_mobile.NewCosmosTransactionOptions(chainId, accountNumber)
}

func NewWalletOptions(useLegacyPath bool) WalletOptions {
	return kos_mobile.NewWalletOptions(useLegacyPath)
}

func NewEthWalletOptions(useLegacyPath bool, chainId uint32) WalletOptions {
	return kos_mobile.NewEthWalletOptions(useLegacyPath, chainId)
}

func NewIcpWalletOptions(useLegacyPath bool, keyType string) WalletOptions {
	return kos_mobile.NewIcpWalletOptions(useLegacyPath, keyType)
}
