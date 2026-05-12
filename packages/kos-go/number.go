package kosgo

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

func Add(lhs, rhs *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberAdd(lhs.inner, rhs.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func Sub(lhs, rhs *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberSubtract(lhs.inner, rhs.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func Mul(lhs, rhs *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberMultiply(lhs.inner, rhs.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func Div(lhs, rhs *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberDivide(lhs.inner, rhs.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func Pow(base, exp *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberPow(base.inner, exp.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func IsEqual(lhs, rhs *BigNumber) bool {
	return kos_mobile.BigNumberIsEqual(lhs.inner, rhs.inner)
}

func IsGt(lhs, rhs *BigNumber) bool {
	return kos_mobile.BigNumberIsGt(lhs.inner, rhs.inner)
}

func IsGte(lhs, rhs *BigNumber) bool {
	return kos_mobile.BigNumberIsGte(lhs.inner, rhs.inner)
}

func IsLt(lhs, rhs *BigNumber) bool {
	return kos_mobile.BigNumberIsLt(lhs.inner, rhs.inner)
}

func IsLte(lhs, rhs *BigNumber) bool {
	return kos_mobile.BigNumberIsLte(lhs.inner, rhs.inner)
}

func Abs(b *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberAbsolute(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func IsZero(b *BigNumber) bool {
	return kos_mobile.BigNumberIsZero(b.inner)
}

func Increment(b *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberIncrement(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func Decrement(b *BigNumber) (*BigNumber, error) {
	result, err := kos_mobile.BigNumberDecrement(b.inner)
	if err != nil {
		return nil, err
	}
	return &BigNumber{inner: result}, nil
}

func IsPositive(b *BigNumber) bool {
	return kos_mobile.BigNumberIsPositive(b.inner)
}

func IsNegative(b *BigNumber) bool {
	return kos_mobile.BigNumberIsNegative(b.inner)
}
