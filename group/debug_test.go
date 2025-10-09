package group

import (
	"fmt"
	"testing"
)

func TestDebugOptimizedOperations(t *testing.T) {
	// Simple test: G + G = 2G
	g := Generator()

	// Regular operations
	resultRegular := Infinity()
	resultRegular.Add(g, g)

	// Optimized operations
	resultOptimized := Infinity()
	resultOptimized.AddOptimized(g, g)

	fmt.Printf("Regular G+G:\n  X: %x\n  Y: %x\n", resultRegular.X().Bytes(), resultRegular.Y().Bytes())
	fmt.Printf("Optimized G+G:\n  X: %x\n  Y: %x\n", resultOptimized.X().Bytes(), resultOptimized.Y().Bytes())

	// Also test doubling
	resultRegularDouble := Infinity()
	resultRegularDouble.Double(g)

	resultOptimizedDouble := Infinity()
	resultOptimizedDouble.DoubleOptimized(g)

	fmt.Printf("Regular 2*G:\n  X: %x\n  Y: %x\n", resultRegularDouble.X().Bytes(), resultRegularDouble.Y().Bytes())
	fmt.Printf("Optimized 2*G:\n  X: %x\n  Y: %x\n", resultOptimizedDouble.X().Bytes(), resultOptimizedDouble.Y().Bytes())
}
