package secp256k1

import "math/big"

var (
	Curve *CurveParams
)

type CurveParams struct {
	// prime definining finite field
	P *big.Int

	// y^2 = x^3 + ax + b
	A int
	B int

	// order n of G
	N *big.Int
	// generator point
	G *Point
}

func init() {
	p := new(big.Int)
	p.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)

	n := new(big.Int)
	n.SetString("0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)

	x := new(big.Int)
	x.SetString("0X79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	gx := &FieldElement{Value: x}

	y := new(big.Int)
	y.SetString("0X483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	gy := &FieldElement{Value: y}

	g := &Point{X: gx, Y: gy, InfinityPoint: false}

	Curve = &CurveParams{P: p, A: 0, B: 7, N: n, G: g}
}
