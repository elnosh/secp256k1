package secp256k1

import (
	"math/big"
)

type FieldElement struct {
	Value *big.Int
}

func (fe *FieldElement) Add(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Add(x.Value, y.Value)
	z.Mod(z, p)
	return &FieldElement{Value: z}
}

func (fe *FieldElement) Sub(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Sub(x.Value, y.Value)
	z.Mod(z, p)
	fe = &FieldElement{Value: z}
	return fe
}

func (fe *FieldElement) Mult(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Mul(x.Value, y.Value)
	z.Mod(z, p)
	fe = &FieldElement{Value: z}
	return fe
}

// Division is done in terms of the multiplicative inverse
// a / b (mod p) == a (b^-1) (mod p)
func (fe *FieldElement) Div(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	inverse := new(big.Int)
	// multiplicative inverse
	inverse.ModInverse(y.Value, p)
	z.Mul(x.Value, inverse)
	z.Mod(z, p)
	fe = &FieldElement{Value: z}
	return fe
}

func (fe *FieldElement) Pow(x *FieldElement, exp *big.Int) *FieldElement {
	z := new(big.Int)
	z.Exp(x.Value, exp, p)
	fe = &FieldElement{Value: z}
	return fe
}

func (fe *FieldElement) Equal(e *FieldElement) bool {
	return fe.Value.Cmp(e.Value) == 0
}

type Point struct {
	X             *FieldElement
	Y             *FieldElement
	InfinityPoint bool
}

func (p *Point) Copy() *Point {
	return &Point{
		X:             p.X,
		Y:             p.Y,
		InfinityPoint: p.InfinityPoint,
	}
}

func (p *Point) Add(p1 *Point, p2 *Point) *Point {
	if p1.InfinityPoint {
		p = &Point{X: p2.X, Y: p2.Y, InfinityPoint: p2.InfinityPoint}
		return p
	}
	if p2.InfinityPoint {
		p = &Point{X: p1.X, Y: p1.Y, InfinityPoint: p1.InfinityPoint}
		return p
	}

	if p1.X.Equal(p2.X) {
		// adding a point to itself
		if p1.Y.Equal(p2.Y) {
			// s = (3x1^2 + a) / 2y1
			var s *FieldElement
			fe3 := &FieldElement{Value: big.NewInt(3)}
			// ignoring a since it is 0
			s.Pow(p1.X, big.NewInt(2)).Mult(s, fe3)
			fe2 := &FieldElement{Value: big.NewInt(2)}
			s.Div(s, fe2.Mult(fe2, p1.Y))

			// x3 = s^2 - 2x1
			var x3 *FieldElement
			fe2 = &FieldElement{Value: big.NewInt(2)}
			x3.Pow(s, big.NewInt(2)).Sub(x3, fe2.Mult(fe2, p1.X))

			// y3 = s(x1 - x3) - y1
			var y3 *FieldElement
			var xt *FieldElement
			xt.Sub(p1.X, x3)
			y3.Mult(s, xt).Sub(y3, p1.Y)

			p = &Point{X: x3, Y: y3, InfinityPoint: false}
			return p
		}

		// same x coordinate but one y is neg
		if p1.Y.Value.CmpAbs(p2.Y.Value) == 0 {
			p = &Point{X: nil, Y: nil, InfinityPoint: true}
			return p
		}
	}

	// slope = (y2 - y1) / (x2 - x1)
	var y *FieldElement
	var x *FieldElement
	y.Sub(p1.Y, p.Y)
	x.Sub(p1.X, p.X)

	var slope *FieldElement
	slope.Div(y, x)

	// x3 = slope^2 - x1 - x2
	var x3 *FieldElement
	x3.Pow(slope, big.NewInt(2)).Sub(x3, p1.X).Sub(x3, p2.X)

	// y3 = slope(x1 - x3) - y1
	var y3 *FieldElement
	y3.Sub(p1.X, x3).Mult(y3, slope).Sub(y3, p1.Y)

	p = &Point{X: x3, Y: y3, InfinityPoint: false}
	return p
}

// does double-and-add algorithm
func (p *Point) ScalarMult(k *big.Int) *Point {
	k.Mod(k, n)

	q := g.Copy()
	r := &Point{InfinityPoint: true}

	for k.Sign() > 0 {
		if new(big.Int).And(k, big.NewInt(1)).Bit(0) == 1 {
			r.Add(r, q)
		}
		q.Add(q, q)
		k.Rsh(k, 1)
	}

	return r
}
