package kosgosigner

import (
	"fmt"

	kos_mobile "github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
)

type Sign = kos_mobile.Sign

const (
	Minus  = kos_mobile.SignMinus
	NoSign = kos_mobile.SignNoSign
	Plus   = kos_mobile.SignPlus
)

type BigNumber struct {
	inner kos_mobile.BigNumber
}

func NewBigNumber(value string) (*BigNumber, error) {
	bn, err := kos_mobile.BigNumberNew(value)
	if err != nil {
		return nil, fmt.Errorf("invalid number: %w", err)
	}
	return &BigNumber{inner: bn}, nil
}

func NewBigNumberZero() *BigNumber {
	return &BigNumber{inner: kos_mobile.BigNumberNewZero()}
}

func (b *BigNumber) String() string {
	return kos_mobile.BigNumberString(b.inner)
}

func (b *BigNumber) Add(other *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberAdd(b.inner, other.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) Sub(other *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberSubtract(b.inner, other.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) Mul(other *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberMultiply(b.inner, other.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) Div(other *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberDivide(b.inner, other.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) Pow(exp *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberPow(b.inner, exp.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) IsEqual(other *BigNumber) bool {
	return kos_mobile.BigNumberIsEqual(b.inner, other.inner)
}

func (b *BigNumber) IsGt(other *BigNumber) bool {
	return kos_mobile.BigNumberIsGt(b.inner, other.inner)
}

func (b *BigNumber) IsGte(other *BigNumber) bool {
	return kos_mobile.BigNumberIsGte(b.inner, other.inner)
}

func (b *BigNumber) IsLt(other *BigNumber) bool {
	return kos_mobile.BigNumberIsLt(b.inner, other.inner)
}

func (b *BigNumber) IsLte(other *BigNumber) bool {
	return kos_mobile.BigNumberIsLte(b.inner, other.inner)
}

func (b *BigNumber) Abs() (*BigNumber, error) {
	result, err := kos_mobile.BigNumberAbsolute(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) IsZero() bool {
	return kos_mobile.BigNumberIsZero(b.inner)
}

func (b *BigNumber) Increment() (*BigNumber, error) {
	result, err := kos_mobile.BigNumberIncrement(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) Decrement() (*BigNumber, error) {
	result, err := kos_mobile.BigNumberDecrement(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func (b *BigNumber) IsPositive() bool {
	return kos_mobile.BigNumberIsPositive(b.inner)
}

func (b *BigNumber) IsNegative() bool {
	return kos_mobile.BigNumberIsNegative(b.inner)
}
