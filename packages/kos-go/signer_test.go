package kosgo

import (
	"fmt"
	"testing"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
)

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestGenerateXpub(t *testing.T) {
	passphrase := ""
	isMainnet := true
	index := uint32(0)

	xpub, err := kos_mobile.GenerateXpub(MNEMONIC, passphrase, isMainnet, index)
	if err != nil {
		t.Fatalf("Failed to generate xpub: %v", err)
	}

	if len(xpub) != 78 {
		t.Errorf("Expected xpub length to be 78, got %d", len(xpub))
	}
}

func TestDeriveXpub(t *testing.T) {
	passphrase := ""
	isMainnet := false
	index := uint32(0)
	derivationPath := "84'/1'/0'"

	derivedXpub, err := kos_mobile.DeriveXpub(MNEMONIC, passphrase, isMainnet, index, derivationPath)
	if err != nil {
		t.Fatalf("Failed to derive xpub: %v", err)
	}

	fmt.Printf("%v\n", []byte(derivedXpub))
	if len(derivedXpub) != 78 {
		t.Errorf("Expected derived xpub length to be 78, got %d", len(derivedXpub))
	}
}
