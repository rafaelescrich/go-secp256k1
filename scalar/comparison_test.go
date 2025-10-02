package scalar

import (
	"testing"
)

func TestScalarComparison(t *testing.T) {
	// Test basic comparison operations
	a := Zero()
	b := Zero()

	// Set a = 1
	a.SetBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	// Set b = 2
	b.SetBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	// Test LessThan
	if !a.LessThan(b) {
		t.Error("1 should be less than 2")
	}

	if b.LessThan(a) {
		t.Error("2 should not be less than 1")
	}

	// Test GreaterThan
	if !b.GreaterThan(a) {
		t.Error("2 should be greater than 1")
	}

	if a.GreaterThan(b) {
		t.Error("1 should not be greater than 2")
	}

	// Test LessThanOrEqual
	if !a.LessThanOrEqual(b) {
		t.Error("1 should be less than or equal to 2")
	}

	if !a.LessThanOrEqual(a) {
		t.Error("1 should be less than or equal to 1")
	}

	// Test GreaterThanOrEqual
	if !b.GreaterThanOrEqual(a) {
		t.Error("2 should be greater than or equal to 1")
	}

	if !a.GreaterThanOrEqual(a) {
		t.Error("1 should be greater than or equal to 1")
	}

	// Test equality
	if !a.Equal(a) {
		t.Error("1 should equal 1")
	}

	if a.Equal(b) {
		t.Error("1 should not equal 2")
	}
}

func TestScalarIsLessThanOrder(t *testing.T) {
	// Test with a small value (should be less than order)
	small := Zero()
	small.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	if !small.IsLessThanOrder() {
		t.Error("Small value should be less than curve order")
	}

	// Test with zero (should be less than order)
	zero := Zero()
	if !zero.IsLessThanOrder() {
		t.Error("Zero should be less than curve order")
	}

	// Test with curve order (should not be less than order)
	// Create curve order using the same method as the constants
	order := Zero()
	order.n[0] = 0xD0364141
	order.n[1] = 0xBFD25E8C
	order.n[2] = 0xAF48A03B
	order.n[3] = 0xBAAEDCE6
	order.n[4] = 0xFFFFFFFE
	order.n[5] = 0xFFFFFFFF
	order.n[6] = 0xFFFFFFFF
	order.n[7] = 0xFFFFFFFF

	if order.IsLessThanOrder() {
		t.Error("Curve order should not be less than itself")
	}
}

func TestScalarComparisonEdgeCases(t *testing.T) {
	// Test with maximum values
	max := Zero()
	max.SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	})

	one := One()

	if !one.LessThan(max) {
		t.Error("1 should be less than max value")
	}

	if !max.GreaterThan(one) {
		t.Error("Max value should be greater than 1")
	}
}
