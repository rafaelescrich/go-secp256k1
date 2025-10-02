package group

// Sub sets p = a - b and returns p.
func (p *Point) Sub(a, b *Point) *Point {
	// Compute a + (-b)
	negB := &Point{}
	negB.Negate(b)
	return p.Add(a, negB)
}
