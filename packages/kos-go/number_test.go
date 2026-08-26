package kosgo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBigNumberNew(t *testing.T) {
	_, err := NewBigNumber("123")
	assert.Nil(t, err)
	_, err = NewBigNumber("-456")
	assert.Nil(t, err)
	_, err = NewBigNumber("0")
	assert.Nil(t, err)

	_, err = NewBigNumber("123.456")
	assert.Nil(t, err)
	_, err = NewBigNumber("-789.012")
	assert.Nil(t, err)
	_, err = NewBigNumber("0.0")
	assert.Nil(t, err)

	_, err = NewBigNumber("abc")
	assert.Error(t, err)
	_, err = NewBigNumber("123a")
	assert.Error(t, err)
	_, err = NewBigNumber("")
	assert.Error(t, err)
}

func TestBigNumberAdd(t *testing.T) {
	a, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Add(a, b)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "579", result.String(), "123 + 456 should equal 579")

	c, err := NewBigNumber("-123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Add(b, c)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "333", result.String(), "456 + (-123) should equal 333")

	d, err := NewBigNumber("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	e, err := NewBigNumber("456.7")
	assert.Nil(t, err, "Failed to create BigNumber")

	result, err = Add(d, e)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "580.2", result.String(), "123.5 + 456.7 should equal 580.2")

	result, err = Add(a, d)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "246.5", result.String(), "123 + 123.5 should equal 246.5")

	f, err := NewBigNumber("123.456")
	assert.Nil(t, err, "Failed to create BigNumber")
	g, err := NewBigNumber("1e5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Add(f, g)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "100123.456", result.String(), "123.456 + 1e5 should equal 100123.456")
}

func TestBigNumberSubtract(t *testing.T) {
	a, err := NewBigNumber("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Sub(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333", result.String(), "456 - 123 should equal 333")

	result, err = Sub(b, a)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "-333", result.String(), "123 - 456 should equal -333")

	c, err := NewBigNumber("456.7")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := NewBigNumber("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Sub(c, d)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333.2", result.String(), "456.7 - 123.5 should equal 333.2")

	result, err = Sub(c, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333.7", result.String(), "456.7 - 123 should equal 333.7")

	a, err = NewBigNumber("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err = NewBigNumber("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Sub(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "0", result.String(), "Subtracting identical values should equal 0")

	a, err = NewBigNumber("1000000000000000.000000000000000000011")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err = NewBigNumber("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Sub(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "0.00000000000000000001", result.String(), "Precise subtraction failed")
}

func TestBigNumberMultiply(t *testing.T) {
	a, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Mul(a, b)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "56088", result.String(), "123 * 456 should equal 56088")

	c, err := NewBigNumber("-123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(c, b)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "-56088", result.String(), "-123 * 456 should equal -56088")

	d, err := NewBigNumber("12.3")
	assert.Nil(t, err, "Failed to create BigNumber")
	e, err := NewBigNumber("4.56")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(d, e)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "56.088", result.String(), "12.3 * 4.56 should equal 56.088")

	zero, err := NewBigNumber("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(a, zero)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "0", result.String(), "123 * 0 should equal 0")

	v1, err := NewBigNumber("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err := NewBigNumber("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "1000000000000000000.0000000002", result.String(), "High precision multiplication failed")

	v1, err = NewBigNumber("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err = NewBigNumber("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "1000000000000000000000000000000.000002", result.String(), "Higher precision multiplication failed")

	v1, err = NewBigNumber("68562856798576893673962586728956729056872")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err = NewBigNumber("4534534534534534534.4456456454772389472398573467326893")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Mul(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "310900641939492821158120256443368825392404212910534543770521.84848435835467083499652468120586", result.String(), "Extremely large number multiplication failed")
}

func TestBigNumberDivide(t *testing.T) {
	a, err := NewBigNumber("100")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Div(a, b)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "20", result.String(), "100 / 5 should equal 20")

	c, err := NewBigNumber("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := NewBigNumber("3")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Div(c, d)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "3.33333333333333333333333333333333", result.String(), "10 / 3 should have correct precision")

	e, err := NewBigNumber("12.6")
	assert.Nil(t, err, "Failed to create BigNumber")
	f, err := NewBigNumber("2.1")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Div(e, f)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "6", result.String(), "12.6 / 2.1 should equal 6")

	v1, err := NewBigNumber("68562856798576893673962586728956729056872")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err := NewBigNumber("4534534534534534534.4456456454772389472398573467326893")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Div(v1, v2)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "15120153188030533505878.87279202398950239411974388454771", result.String(), "Division of large numbers failed")

	a1, err := NewBigNumber("115792089237316195423570985008687907853269984665640564039457584007913129639935")
	assert.Nil(t, err, "Failed to create BigNumber")
	b2, err := NewBigNumber("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Div(a1, b2)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "57896044618658097711785492504343953926634992332820282019728792003956564819967.5", result.String(), "Division of very large number failed")
}

func TestBigNumberIsZero(t *testing.T) {
	zero, err := NewBigNumber("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	zeroDecimal, err := NewBigNumber("0.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	nonZero, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")

	assert.True(t, IsZero(zero), "BigNumberIsZero(0) should be true")
	assert.True(t, IsZero(zeroDecimal), "BigNumberIsZero(0.0) should be true")
	assert.False(t, IsZero(nonZero), "BigNumberIsZero(123) should be false")
}

func TestBigNumberIncrementDecrement(t *testing.T) {
	a, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Increment(a)
	assert.Nil(t, err, "Failed to increment number")
	assert.Equal(t, "124", result.String(), "123 + 1 should equal 124")

	b, err := NewBigNumber("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Increment(b)
	assert.Nil(t, err, "Failed to increment number")
	assert.Equal(t, "124.5", result.String(), "123.5 + 1 should equal 124.5")

	c, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Decrement(c)
	assert.Nil(t, err, "Failed to decrement number")
	assert.Equal(t, "122", result.String(), "123 - 1 should equal 122")

	d, err := NewBigNumber("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Decrement(d)
	assert.Nil(t, err, "Failed to decrement number")
	assert.Equal(t, "122.5", result.String(), "123.5 - 1 should equal 122.5")
}

func TestBigNumberIsPositiveNegative(t *testing.T) {
	a, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, IsPositive(a), "123 should be positive")
	assert.False(t, IsNegative(a), "123 should not be negative")

	b, err := NewBigNumber("-456")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, IsPositive(b), "-456 should not be positive")
	assert.True(t, IsNegative(b), "-456 should be negative")

	c, err := NewBigNumber("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, IsPositive(c), "0 should not be positive")
	assert.False(t, IsNegative(c), "0 should not be negative")
}

func TestBigNumberIsEqual(t *testing.T) {
	a, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, IsEqual(a, b), "123 should equal 123")

	c, err := NewBigNumber("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, IsEqual(a, c), "123 should not equal 456")

	d, err := NewBigNumber("123.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, IsEqual(a, d), "123 should equal 123.0")

	e, err := NewBigNumber("123.000")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, IsEqual(a, e), "123 should equal 123.000")
}

func TestBigNumberComparison(t *testing.T) {
	a, err := NewBigNumber("100")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := NewBigNumber("200")
	assert.Nil(t, err, "Failed to create BigNumber")
	c, err := NewBigNumber("100.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := NewBigNumber("100.5")
	assert.Nil(t, err, "Failed to create BigNumber")

	assert.True(t, IsGt(b, a), "200 should be > 100")
	assert.False(t, IsGt(a, b), "100 should not be > 200")
	assert.False(t, IsGt(a, c), "100 should not be > 100.0")
	assert.True(t, IsGt(d, a), "100.5 should be > 100")

	assert.True(t, IsGte(b, a), "200 should be >= 100")
	assert.True(t, IsGte(a, c), "100 should be >= 100.0")
	assert.False(t, IsGte(a, b), "100 should not be >= 200")
	assert.True(t, IsGte(d, c), "100.5 should be >= 100.0")

	assert.True(t, IsLt(a, b), "100 should be < 200")
	assert.False(t, IsLt(b, a), "200 should not be < 100")
	assert.False(t, IsLt(c, a), "100.0 should not be < 100")
	assert.True(t, IsLt(c, d), "100.0 should be < 100.5")

	assert.True(t, IsLte(a, b), "100 should be <= 200")
	assert.True(t, IsLte(c, a), "100.0 should be <= 100")
	assert.False(t, IsLte(b, a), "200 should not be <= 100")
	assert.True(t, IsLte(a, c), "100 should be <= 100.0")
}

func TestBigNumberPow(t *testing.T) {
	base, err := NewBigNumber("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp, err := NewBigNumber("3")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Pow(base, exp)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "8", result.String(), "2^3 should equal 8")

	zero, err := NewBigNumber("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Pow(base, zero)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "1", result.String(), "2^0 should equal 1")

	ten, err := NewBigNumber("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp10, err := NewBigNumber("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Pow(ten, exp10)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "10000000000", result.String(), "10^10 should equal 10000000000")

	baseDec, err := NewBigNumber("2.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp2, err := NewBigNumber("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Pow(baseDec, exp2)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "6.25", result.String(), "2.5^2 should equal 6.25")

	negExp, err := NewBigNumber("-1")
	assert.Nil(t, err, "Failed to create BigNumber")

	_, err = Pow(base, negExp)
	assert.Error(t, err, "Should return error for negative exponent")
}

func TestBigNumberAbsolute(t *testing.T) {
	positive, err := NewBigNumber("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := Abs(positive)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123", result.String(), "abs(123) should equal 123")

	negative, err := NewBigNumber("-456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Abs(negative)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "456", result.String(), "abs(-456) should equal 456")

	zero, err := NewBigNumber("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Abs(zero)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "0", result.String(), "abs(0) should equal 0")

	posDec, err := NewBigNumber("123.45")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Abs(posDec)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123.45", result.String(), "abs(123.45) should equal 123.45")

	negDec, err := NewBigNumber("-123.45")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = Abs(negDec)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123.45", result.String(), "abs(-123.45) should equal 123.45")
}
