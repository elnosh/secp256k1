package ecdsa

import (
	"math/big"

	"github.com/elnosh/secp256k1"
)

type Signature struct {
	// both r and s will be modulo n so I could
	// use Scalar type here instead big.Int
	r *big.Int
	s *big.Int
}

func Sign(key *secp256k1.PrivateKey, hash []byte) (*Signature, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	// r is the x value of the ephemeral key
	r := new(big.Int).Set(k.PublicKey.X.Value)
	e := new(big.Int).SetBytes(hash)

	// signature s = k^-1 (e+r*key) mod n
	s := new(big.Int)
	s.Mul(r, key.SecretKey.N).Add(s, e)
	kinverse := new(big.Int)
	kinverse.ModInverse(k.SecretKey.N, secp256k1.Curve.N)
	s.Mul(s, kinverse).Mod(s, secp256k1.Curve.N)

	signature := &Signature{r, s}
	return signature, nil
}

func (s *Signature) Verify(publicKey *secp256k1.PublicKey, hash []byte) bool {
	if s.r.Cmp(secp256k1.Curve.N) > 0 || s.s.Cmp(secp256k1.Curve.N) > 0 {
		return false
	}

	e := new(big.Int).SetBytes(hash)

	// u1 = es^-1 mod n
	sinverse := new(big.Int).ModInverse(s.s, secp256k1.Curve.N)
	u1 := new(big.Int)
	u1.Mul(e, sinverse).Mod(u1, secp256k1.Curve.N)

	// u2 = rs^-1 mod n
	u2 := new(big.Int)
	u2.Mul(s.r, sinverse).Mod(u2, secp256k1.Curve.N)

	u1Scalar, err := secp256k1.NewScalar(u1)
	if err != nil {
		return false
	}

	u2Scalar, err := secp256k1.NewScalar(u2)
	if err != nil {
		return false
	}

	//  u1*G
	u1Point := secp256k1.BaseScalarMult(u1Scalar)
	// u2*PublicKey
	u2PubKeyPoint := secp256k1.ScalarMult(u2Scalar, publicKey.Point)

	// R = u1*G + u2*PublicKey
	RPoint := new(secp256k1.Point)
	RPoint = RPoint.Add(u1Point, u2PubKeyPoint)

	// u = R.x
	u := new(big.Int).Set(RPoint.X.Value)
	u.Mod(u, secp256k1.Curve.N)

	// signature is valid if u == r
	if u.Cmp(s.r) != 0 {
		return false
	}

	return true
}
