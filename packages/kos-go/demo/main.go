package main

import (
	"fmt"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
)

func main() {
	chainID := uint32(48)

	walletOptions := kos_mobile.WalletOptions{
		UseLegacyPath: false,
		Specific:      nil,
	}
	account, err := kos_mobile.GenerateWalletFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		chainID,
		0,
		&walletOptions,
	)
	if err != nil {
		fmt.Println("Failed to generate wallet from mnemonic: ", err)
		return
	}

	options := kos_mobile.NewCosmosTransactionOptions("celestia", 274454)

	transaction, err := kos_mobile.SignTransaction(
		account,
		"0a94010a8d010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126d0a2f63656c65737469613173706b326e686a6d67706d37713767796d753839727a37636c686e34787578757a3430717566122f63656c65737469613130377871366b787036353471666832643872687171736d36793364656a7237396130367479631a090a047574696112013112026f6912670a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21020271b9bc2af1a68367375a64337f1cdbfae718217946d45e5ee1b83c312291a212040a020801180312130a0d0a04757469611205323530303010aa8c06",
		&options,
	)
	if err != nil {
		fmt.Println("Failed to sign transaction: ", err)
		return
	}

	fmt.Println(transaction)
}
