package secp256k1

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type FieldElement struct {
	Value *big.Int
}

func NewFieldElement(n *big.Int) *FieldElement {
	value := new(big.Int).Set(n)
	return &FieldElement{Value: value}
}

func (fe *FieldElement) Add(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Add(x.Value, y.Value)
	z.Mod(z, Curve.P)
	fe.Value = z
	return fe
}

func (fe *FieldElement) Sub(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Sub(x.Value, y.Value)
	z.Mod(z, Curve.P)
	fe.Value = z
	return fe
}

func (fe *FieldElement) Mult(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	z.Mul(x.Value, y.Value)
	z.Mod(z, Curve.P)
	fe.Value = z
	return fe
}

// Division is done in terms of the multiplicative inverse
// a / b (mod p) == a (b^-1) (mod p)
func (fe *FieldElement) Div(x, y *FieldElement) *FieldElement {
	z := new(big.Int)
	inverse := new(big.Int)
	// multiplicative inverse
	inverse.ModInverse(y.Value, Curve.P)
	z.Mul(x.Value, inverse)
	z.Mod(z, Curve.P)
	fe.Value = z
	return fe
}

func (fe *FieldElement) Pow(x *FieldElement, exp *big.Int) *FieldElement {
	z := new(big.Int)
	z.Exp(x.Value, exp, Curve.P)
	fe.Value = z
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
		X:             NewFieldElement(p.X.Value),
		Y:             NewFieldElement(p.Y.Value),
		InfinityPoint: p.InfinityPoint,
	}
}

func (p *Point) Add(p1 *Point, p2 *Point) *Point {
	if p1.InfinityPoint {
		p.X = p2.X
		p.Y = p2.Y
		p.InfinityPoint = p2.InfinityPoint
		return p
	}
	if p2.InfinityPoint {
		p.X = p1.X
		p.Y = p1.Y
		p.InfinityPoint = p1.InfinityPoint
		return p
	}

	if p1.X.Equal(p2.X) {
		// adding a point to itself
		if p1.Y.Equal(p2.Y) {
			// s = (3x1^2 + a) / 2y1
			s := new(FieldElement)
			fe3 := &FieldElement{Value: big.NewInt(3)}
			// ignoring a since it is 0
			s.Pow(p1.X, big.NewInt(2)).Mult(s, fe3)

			fe2 := &FieldElement{Value: big.NewInt(2)}
			s.Div(s, fe2.Mult(fe2, p1.Y))

			// x3 = s^2 - 2x1
			x3 := new(FieldElement)
			fe2 = &FieldElement{Value: big.NewInt(2)}
			x3.Pow(s, big.NewInt(2))
			x3.Sub(x3, fe2.Mult(fe2, p1.X))

			// y3 = s(x1 - x3) - y1
			y3 := new(FieldElement)
			y3.Sub(p1.X, x3).Mult(y3, s).Sub(y3, p1.Y)

			p.X = x3
			p.Y = y3
			p.InfinityPoint = false
			return p
		}

		// same x coordinate but one y is neg
		if p1.Y.Value.CmpAbs(p2.Y.Value) == 0 {
			p.X = nil
			p.Y = nil
			p.InfinityPoint = true
			return p
		}
	}

	// slope = (y2 - y1) / (x2 - x1)
	y := new(FieldElement)
	x := new(FieldElement)

	y.Sub(p2.Y, p1.Y)
	x.Sub(p2.X, p1.X)

	slope := new(FieldElement)
	slope.Div(y, x)

	// x3 = slope^2 - x1 - x2
	x3 := new(FieldElement)
	x3.Pow(slope, big.NewInt(2)).Sub(x3, p1.X).Sub(x3, p2.X)

	// y3 = slope(x1 - x3) - y1
	y3 := new(FieldElement)
	y3.Sub(p1.X, x3).Mult(y3, slope).Sub(y3, p1.Y)

	p.X = x3
	p.Y = y3
	p.InfinityPoint = false
	return p
}

// big integer modulo n
type Scalar struct {
	N *big.Int
}

func NewScalar(number *big.Int) (*Scalar, error) {
	if number.Cmp(Curve.N) > 0 {
		return nil, fmt.Errorf("scalar needs to be less than n")
	}

	return &Scalar{N: number}, nil
}

// does double-and-add algorithm
// k*G
func BaseScalarMult(k *Scalar) *Point {
	q := Curve.G.Copy()
	r := &Point{InfinityPoint: true}

	kInt := new(big.Int).Set(k.N)

	for kInt.Sign() > 0 {
		if new(big.Int).And(kInt, big.NewInt(1)).Bit(0) == 1 {
			r.Add(r, q)
		}
		q.Add(q, q)
		kInt.Rsh(kInt, 1)
	}

	return r
}

func ScalarMult(k *Scalar, p *Point) *Point {
	q := p.Copy()
	r := &Point{InfinityPoint: true}

	kInt := new(big.Int).Set(k.N)

	for kInt.Sign() > 0 {
		if new(big.Int).And(kInt, big.NewInt(1)).Bit(0) == 1 {
			r.Add(r, q)
		}
		q.Add(q, q)
		kInt.Rsh(kInt, 1)
	}

	return r
}

type PrivateKey struct {
	SecretKey *Scalar
	PublicKey *PublicKey
}

func NewPrivateKey(scalar *Scalar) *PrivateKey {
	point := BaseScalarMult(scalar)
	publicKey := &PublicKey{point}
	return &PrivateKey{SecretKey: scalar, PublicKey: publicKey}
}

func GeneratePrivateKey() (*PrivateKey, error) {
	random, err := rand.Int(rand.Reader, Curve.N)
	if err != nil {
		return nil, err
	}
	scalar, err := NewScalar(random)
	if err != nil {
		return nil, err
	}
	k := NewPrivateKey(scalar)
	return k, nil
}

type PublicKey struct {
	*Point
}
