package main

import (
	"encoding/hex"
	"fmt"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
)

func main() {
	chainID := uint32(18) // BCH

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

	rawTx := "0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d0100000000ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c0100000000ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000"

	prevScript1, _ := hex.DecodeString("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac")
	prevScript2, _ := hex.DecodeString("76a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac")

	var options kos_mobile.TransactionChainOptions = kos_mobile.TransactionChainOptions(kos_mobile.TransactionChainOptionsBtc{
		InputAmounts: []uint64{498870, 1001016},
		PrevScripts:  [][]byte{prevScript1, prevScript2},
	})
	transaction, err := kos_mobile.SignTransaction(account, rawTx, &options)
	if err != nil {
		fmt.Printf("failed to sign transaction: %v", err)
	}

	expectedRaw :=
		"0100000002afa8838dbaa03cd3e4fee38bdcb6a428965559ae941dca5a8f91999cfd6d8b0d010000006b48304502210099626d28374fa3d1a0034330fee7745ab02db07cd37649e6d3ffbe046ff92e9402203793bee2372ab59a05b45188c2bace3b48e73209a01e4d5d862925971632c80a412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffffdb6d60d4a93a95738e72f641bcdd166c94f6e1f439dfe695e40583997284463c010000006a4730440220447084aae4c6800db7c86b8bc8da675e464991a035b2b4010cde48b64a1013a10220582acfb5265c22eae9c2880e07ae66fc86cbef2e97a2ca1bc513535ba322360d412102bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217ffffffff0240420f00000000001976a91434bf902df5d66f0e9b89d0f83fbcad638ad19ae988acea970700000000001976a9145bb0ba5ba58cdab459f27f2d29f40e1dd5db238188ac00000000"

	if transaction.Raw != expectedRaw {
		fmt.Printf("The raw doesn't match.\nExpected: %s\nGot: %s\n", expectedRaw, transaction.Raw)
	}

	fmt.Printf("Signed raw transaction:\n%s\n", transaction.Raw)
}
