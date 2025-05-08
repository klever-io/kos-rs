package kosgo

import (
	"testing"

	"github.com/klever-io/kos-rs/packages/kos-go/kos_mobile"
	"github.com/stretchr/testify/assert"
)

func TestBigNumberNew(t *testing.T) {
	_, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err)
	_, err = kos_mobile.BigNumberNew("-456")
	assert.Nil(t, err)
	_, err = kos_mobile.BigNumberNew("0")
	assert.Nil(t, err)

	_, err = kos_mobile.BigNumberNew("123.456")
	assert.Nil(t, err)
	_, err = kos_mobile.BigNumberNew("-789.012")
	assert.Nil(t, err)
	_, err = kos_mobile.BigNumberNew("0.0")
	assert.Nil(t, err)

	_, err = kos_mobile.BigNumberNew("abc")
	assert.Error(t, err)
	_, err = kos_mobile.BigNumberNew("123a")
	assert.Error(t, err)
	_, err = kos_mobile.BigNumberNew("")
	assert.Error(t, err)
}

func TestBigNumberAdd(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberAdd(a, b)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "579", kos_mobile.BigNumberString(result), "123 + 456 should equal 579")

	c, err := kos_mobile.BigNumberNew("-123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAdd(b, c)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "333", kos_mobile.BigNumberString(result), "456 + (-123) should equal 333")

	d, err := kos_mobile.BigNumberNew("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	e, err := kos_mobile.BigNumberNew("456.7")
	assert.Nil(t, err, "Failed to create BigNumber")

	result, err = kos_mobile.BigNumberAdd(d, e)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "580.2", kos_mobile.BigNumberString(result), "123.5 + 456.7 should equal 580.2")

	result, err = kos_mobile.BigNumberAdd(a, d)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "246.5", kos_mobile.BigNumberString(result), "123 + 123.5 should equal 246.5")

	f, err := kos_mobile.BigNumberNew("123.456")
	assert.Nil(t, err, "Failed to create BigNumber")
	g, err := kos_mobile.BigNumberNew("1e5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAdd(f, g)
	assert.Nil(t, err, "Failed to add numbers")
	assert.Equal(t, "100123.456", kos_mobile.BigNumberString(result), "123.456 + 1e5 should equal 100123.456")
}

func TestBigNumberSubtract(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberSubtract(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333", kos_mobile.BigNumberString(result), "456 - 123 should equal 333")

	result, err = kos_mobile.BigNumberSubtract(b, a)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "-333", kos_mobile.BigNumberString(result), "123 - 456 should equal -333")

	c, err := kos_mobile.BigNumberNew("456.7")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := kos_mobile.BigNumberNew("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberSubtract(c, d)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333.2", kos_mobile.BigNumberString(result), "456.7 - 123.5 should equal 333.2")

	result, err = kos_mobile.BigNumberSubtract(c, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "333.7", kos_mobile.BigNumberString(result), "456.7 - 123 should equal 333.7")

	a, err = kos_mobile.BigNumberNew("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err = kos_mobile.BigNumberNew("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberSubtract(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "0", kos_mobile.BigNumberString(result), "Subtracting identical values should equal 0")

	a, err = kos_mobile.BigNumberNew("1000000000000000.000000000000000000011")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err = kos_mobile.BigNumberNew("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberSubtract(a, b)
	assert.Nil(t, err, "Failed to subtract numbers")
	assert.Equal(t, "0.00000000000000000001", kos_mobile.BigNumberString(result), "Precise subtraction failed")
}

func TestBigNumberMultiply(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberMultiply(a, b)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "56088", kos_mobile.BigNumberString(result), "123 * 456 should equal 56088")

	c, err := kos_mobile.BigNumberNew("-123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(c, b)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "-56088", kos_mobile.BigNumberString(result), "-123 * 456 should equal -56088")

	d, err := kos_mobile.BigNumberNew("12.3")
	assert.Nil(t, err, "Failed to create BigNumber")
	e, err := kos_mobile.BigNumberNew("4.56")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(d, e)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "56.088", kos_mobile.BigNumberString(result), "12.3 * 4.56 should equal 56.088")

	zero, err := kos_mobile.BigNumberNew("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(a, zero)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "0", kos_mobile.BigNumberString(result), "123 * 0 should equal 0")

	v1, err := kos_mobile.BigNumberNew("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err := kos_mobile.BigNumberNew("1000000000.0000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "1000000000000000000.0000000002", kos_mobile.BigNumberString(result),
		"High precision multiplication failed")

	v1, err = kos_mobile.BigNumberNew("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err = kos_mobile.BigNumberNew("1000000000000000.000000000000000000001")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "1000000000000000000000000000000.000002", kos_mobile.BigNumberString(result),
		"Higher precision multiplication failed")

	v1, err = kos_mobile.BigNumberNew("68562856798576893673962586728956729056872")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err = kos_mobile.BigNumberNew("4534534534534534534.4456456454772389472398573467326893")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberMultiply(v1, v2)
	assert.Nil(t, err, "Failed to multiply numbers")
	assert.Equal(t, "310900641939492821158120256443368825392404212910534543770521.84848435835467083499652468120586",
		kos_mobile.BigNumberString(result), "Extremely large number multiplication failed")
}

func TestBigNumberDivide(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("100")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberDivide(a, b)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "20", kos_mobile.BigNumberString(result), "100 / 5 should equal 20")

	c, err := kos_mobile.BigNumberNew("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := kos_mobile.BigNumberNew("3")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDivide(c, d)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "3.33333333333333333333333333333333", kos_mobile.BigNumberString(result), "10 / 3 should have correct precision")

	e, err := kos_mobile.BigNumberNew("12.6")
	assert.Nil(t, err, "Failed to create BigNumber")
	f, err := kos_mobile.BigNumberNew("2.1")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDivide(e, f)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "6", kos_mobile.BigNumberString(result), "12.6 / 2.1 should equal 6")

	v1, err := kos_mobile.BigNumberNew("68562856798576893673962586728956729056872")
	assert.Nil(t, err, "Failed to create BigNumber")
	v2, err := kos_mobile.BigNumberNew("4534534534534534534.4456456454772389472398573467326893")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDivide(v1, v2)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "15120153188030533505878.87279202398950239411974388454771", kos_mobile.BigNumberString(result), "Division of large numbers failed")

	a1, err := kos_mobile.BigNumberNew("115792089237316195423570985008687907853269984665640564039457584007913129639935")
	assert.Nil(t, err, "Failed to create BigNumber")
	b2, err := kos_mobile.BigNumberNew("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDivide(a1, b2)
	assert.Nil(t, err, "Failed to divide numbers")
	assert.Equal(t, "57896044618658097711785492504343953926634992332820282019728792003956564819967.5", kos_mobile.BigNumberString(result), "Division of very large number failed")
}

func TestBigNumberIsZero(t *testing.T) {
	zero, err := kos_mobile.BigNumberNew("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	zeroDecimal, err := kos_mobile.BigNumberNew("0.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	nonZero, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")

	assert.True(t, kos_mobile.BigNumberIsZero(zero), "BigNumberIsZero(0) should be true")
	assert.True(t, kos_mobile.BigNumberIsZero(zeroDecimal), "BigNumberIsZero(0.0) should be true")
	assert.False(t, kos_mobile.BigNumberIsZero(nonZero), "BigNumberIsZero(123) should be false")
}

func TestBigNumberIncrementDecrement(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberIncrement(a)
	assert.Nil(t, err, "Failed to increment number")
	assert.Equal(t, "124", kos_mobile.BigNumberString(result), "123 + 1 should equal 124")

	b, err := kos_mobile.BigNumberNew("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberIncrement(b)
	assert.Nil(t, err, "Failed to increment number")
	assert.Equal(t, "124.5", kos_mobile.BigNumberString(result), "123.5 + 1 should equal 124.5")

	c, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDecrement(c)
	assert.Nil(t, err, "Failed to decrement number")
	assert.Equal(t, "122", kos_mobile.BigNumberString(result), "123 - 1 should equal 122")

	d, err := kos_mobile.BigNumberNew("123.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberDecrement(d)
	assert.Nil(t, err, "Failed to decrement number")
	assert.Equal(t, "122.5", kos_mobile.BigNumberString(result), "123.5 - 1 should equal 122.5")
}

func TestBigNumberIsPositiveNegative(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, kos_mobile.BigNumberIsPositive(a), "123 should be positive")
	assert.False(t, kos_mobile.BigNumberIsNegative(a), "123 should not be negative")

	b, err := kos_mobile.BigNumberNew("-456")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, kos_mobile.BigNumberIsPositive(b), "-456 should not be positive")
	assert.True(t, kos_mobile.BigNumberIsNegative(b), "-456 should be negative")

	c, err := kos_mobile.BigNumberNew("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, kos_mobile.BigNumberIsPositive(c), "0 should not be positive")
	assert.False(t, kos_mobile.BigNumberIsNegative(c), "0 should not be negative")
}

func TestBigNumberIsEqual(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, kos_mobile.BigNumberIsEqual(a, b), "123 should equal 123")

	c, err := kos_mobile.BigNumberNew("456")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.False(t, kos_mobile.BigNumberIsEqual(a, c), "123 should not equal 456")

	d, err := kos_mobile.BigNumberNew("123.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, kos_mobile.BigNumberIsEqual(a, d), "123 should equal 123.0")

	e, err := kos_mobile.BigNumberNew("123.000")
	assert.Nil(t, err, "Failed to create BigNumber")
	assert.True(t, kos_mobile.BigNumberIsEqual(a, e), "123 should equal 123.000")
}

func TestBigNumberComparison(t *testing.T) {
	a, err := kos_mobile.BigNumberNew("100")
	assert.Nil(t, err, "Failed to create BigNumber")
	b, err := kos_mobile.BigNumberNew("200")
	assert.Nil(t, err, "Failed to create BigNumber")
	c, err := kos_mobile.BigNumberNew("100.0")
	assert.Nil(t, err, "Failed to create BigNumber")
	d, err := kos_mobile.BigNumberNew("100.5")
	assert.Nil(t, err, "Failed to create BigNumber")

	assert.True(t, kos_mobile.BigNumberIsGt(b, a), "200 should be > 100")
	assert.False(t, kos_mobile.BigNumberIsGt(a, b), "100 should not be > 200")
	assert.False(t, kos_mobile.BigNumberIsGt(a, c), "100 should not be > 100.0")
	assert.True(t, kos_mobile.BigNumberIsGt(d, a), "100.5 should be > 100")

	assert.True(t, kos_mobile.BigNumberIsGte(b, a), "200 should be >= 100")
	assert.True(t, kos_mobile.BigNumberIsGte(a, c), "100 should be >= 100.0")
	assert.False(t, kos_mobile.BigNumberIsGte(a, b), "100 should not be >= 200")
	assert.True(t, kos_mobile.BigNumberIsGte(d, c), "100.5 should be >= 100.0")

	assert.True(t, kos_mobile.BigNumberIsLt(a, b), "100 should be < 200")
	assert.False(t, kos_mobile.BigNumberIsLt(b, a), "200 should not be < 100")
	assert.False(t, kos_mobile.BigNumberIsLt(c, a), "100.0 should not be < 100")
	assert.True(t, kos_mobile.BigNumberIsLt(c, d), "100.0 should be < 100.5")

	assert.True(t, kos_mobile.BigNumberIsLte(a, b), "100 should be <= 200")
	assert.True(t, kos_mobile.BigNumberIsLte(c, a), "100.0 should be <= 100")
	assert.False(t, kos_mobile.BigNumberIsLte(b, a), "200 should not be <= 100")
	assert.True(t, kos_mobile.BigNumberIsLte(a, c), "100 should be <= 100.0")
}

func TestBigNumberPow(t *testing.T) {
	base, err := kos_mobile.BigNumberNew("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp, err := kos_mobile.BigNumberNew("3")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberPow(base, exp)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "8", kos_mobile.BigNumberString(result), "2^3 should equal 8")

	zero, err := kos_mobile.BigNumberNew("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberPow(base, zero)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "1", kos_mobile.BigNumberString(result), "2^0 should equal 1")

	ten, err := kos_mobile.BigNumberNew("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp10, err := kos_mobile.BigNumberNew("10")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberPow(ten, exp10)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "10000000000", kos_mobile.BigNumberString(result), "10^10 should equal 10000000000")

	baseDec, err := kos_mobile.BigNumberNew("2.5")
	assert.Nil(t, err, "Failed to create BigNumber")
	exp2, err := kos_mobile.BigNumberNew("2")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberPow(baseDec, exp2)
	assert.Nil(t, err, "Failed to calculate power")
	assert.Equal(t, "6.25", kos_mobile.BigNumberString(result), "2.5^2 should equal 6.25")

	negExp, err := kos_mobile.BigNumberNew("-1")
	assert.Nil(t, err, "Failed to create BigNumber")

	_, err = kos_mobile.BigNumberPow(base, negExp)
	assert.Error(t, err, "Should return error for negative exponent")
}

func TestBigNumberAbsolute(t *testing.T) {
	positive, err := kos_mobile.BigNumberNew("123")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err := kos_mobile.BigNumberAbsolute(positive)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123", kos_mobile.BigNumberString(result), "abs(123) should equal 123")

	negative, err := kos_mobile.BigNumberNew("-456")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAbsolute(negative)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "456", kos_mobile.BigNumberString(result), "abs(-456) should equal 456")

	zero, err := kos_mobile.BigNumberNew("0")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAbsolute(zero)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "0", kos_mobile.BigNumberString(result), "abs(0) should equal 0")

	posDec, err := kos_mobile.BigNumberNew("123.45")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAbsolute(posDec)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123.45", kos_mobile.BigNumberString(result), "abs(123.45) should equal 123.45")

	negDec, err := kos_mobile.BigNumberNew("-123.45")
	assert.Nil(t, err, "Failed to create BigNumber")
	result, err = kos_mobile.BigNumberAbsolute(negDec)
	assert.Nil(t, err, "Failed to calculate absolute")
	assert.Equal(t, "123.45", kos_mobile.BigNumberString(result), "abs(-123.45) should equal 123.45")
}
