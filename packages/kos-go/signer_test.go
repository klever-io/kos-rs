package kosgo

import (
	"fmt"
	"testing"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
	"github.com/stretchr/testify/assert"
)

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestGenerateXpub(t *testing.T) {
	passphrase := ""
	isMainnet := true
	index := uint32(0)

	xpub, err := kos_mobile.GenerateXpub(MNEMONIC, passphrase, isMainnet, index)

	assert.Nil(t, err, "Failed to generate xpub")
	assert.Equal(t, 78, len(xpub), "Expected xpub length to be 78")
}

func TestDeriveXpub(t *testing.T) {
	passphrase := ""
	isMainnet := false
	index := uint32(0)
	derivationPath := "84'/1'/0'"

	derivedXpub, err := kos_mobile.DeriveXpub(MNEMONIC, passphrase, isMainnet, index, derivationPath)

	assert.Nil(t, err, "Failed to derive xpub")
	fmt.Printf("%v\n", []byte(derivedXpub))
	assert.Equal(t, 78, len(derivedXpub), "Expected derived xpub length to be 78")
}
