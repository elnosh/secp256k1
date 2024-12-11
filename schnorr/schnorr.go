package schnorr

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/elnosh/secp256k1"
)

type Signature struct {
	r *big.Int
	s *big.Int
}

func Sign(key *secp256k1.PrivateKey, hash []byte) (*Signature, error) {
	a, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return sign(key, hash, a)
}

func sign(key *secp256k1.PrivateKey, hash []byte, nonce *secp256k1.PrivateKey) (*Signature, error) {
	sk := key.Copy()

	y := new(big.Int).Set(sk.PublicKey.Y.Value)
	mod := new(big.Int).Mod(y, big.NewInt(2))
	// negate secret key if y-coordinate is not even
	if mod.Cmp(big.NewInt(0)) != 0 {
		d := new(big.Int).Sub(secp256k1.Curve.N, sk.SecretKey.N)
		dScalar, err := secp256k1.NewScalar(d)
		if err != nil {
			return nil, err
		}
		sk = secp256k1.NewPrivateKey(dScalar)
	}

	// xor sk and hash_bip340/aux_tagged(a)
	nonceBuf := make([]byte, 32)
	auxHash := TaggedHash("BIP0340/aux", nonce.SecretKey.N.FillBytes(nonceBuf))

	t := new(big.Int)
	t.Xor(sk.SecretKey.N, new(big.Int).SetBytes(auxHash))

	tbuf := make([]byte, 32)
	pubkeybuf := make([]byte, 32)
	randBytes := bytes.Join([][]byte{t.FillBytes(tbuf), sk.PublicKey.X.Value.FillBytes(pubkeybuf), hash}, nil)
	rand := TaggedHash("BIP0340/nonce", randBytes)

	kint := new(big.Int).SetBytes(rand)
	kint.Mod(kint, secp256k1.Curve.N)
	mod = new(big.Int).Mod(kint, secp256k1.Curve.N)
	if mod.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("could not generate signature")
	}

	kScalar, err := secp256k1.NewScalar(kint)
	if err != nil {
		return nil, err
	}

	k := secp256k1.NewPrivateKey(kScalar)
	y = new(big.Int).Set(k.PublicKey.Y.Value)
	mod = new(big.Int).Mod(y, big.NewInt(2))
	if k.PublicKey.InfinityPoint || mod.Cmp(big.NewInt(0)) != 0 {
		kint := new(big.Int).Sub(secp256k1.Curve.N, kint)
		kScalar, err := secp256k1.NewScalar(kint)
		if err != nil {
			return nil, err
		}
		k = secp256k1.NewPrivateKey(kScalar)
	}

	Rbuf := make([]byte, 32)
	ebytes := bytes.Join([][]byte{k.PublicKey.X.Value.FillBytes(Rbuf), pubkeybuf, hash}, nil)
	challengeHash := TaggedHash("BIP0340/challenge", ebytes)
	e := new(big.Int).SetBytes(challengeHash)
	e.Mod(e, secp256k1.Curve.N)

	s := new(big.Int).Set(k.SecretKey.N)
	s.Add(s, e.Mul(e, sk.SecretKey.N)).Mod(s, secp256k1.Curve.N)

	return &Signature{r: k.PublicKey.X.Value, s: s}, nil
}

func (s *Signature) Verify(pubkey *secp256k1.PublicKey, hash []byte) bool {
	y := new(big.Int).Set(pubkey.Y.Value)
	mod := new(big.Int).Mod(y, big.NewInt(2))
	// fail if y-coordinate of public key is not even
	if mod.Cmp(big.NewInt(0)) != 0 {
		return false
	}

	if s.r.Cmp(secp256k1.Curve.P) >= 0 {
		return false
	}
	if s.s.Cmp(secp256k1.Curve.N) >= 0 {
		return false
	}

	rbuf := make([]byte, 32)
	pubkeybuf := make([]byte, 32)
	ebytes := bytes.Join([][]byte{s.r.FillBytes(rbuf), pubkey.X.Value.FillBytes(pubkeybuf), hash}, nil)
	challengeHash := TaggedHash("BIP0340/challenge", ebytes)
	e := new(big.Int).SetBytes(challengeHash)
	e.Mod(e, secp256k1.Curve.N)

	sScalar, err := secp256k1.NewScalar(s.s)
	if err != nil {
		return false
	}

	eScalar, err := secp256k1.NewScalar(e)
	if err != nil {
		return false
	}

	R := secp256k1.BaseScalarMult(sScalar)
	eP := secp256k1.ScalarMult(eScalar, pubkey.Point)
	R.Add(R, eP.Inverse())

	if R.InfinityPoint {
		return false
	}

	RY := new(big.Int).Set(R.Y.Value)
	mod = new(big.Int).Mod(RY, big.NewInt(2))
	if mod.Cmp(big.NewInt(0)) != 0 {
		return false
	}

	if R.X.Value.Cmp(s.r) != 0 {
		return false
	}

	return true
}

func TaggedHash(tag string, x []byte) []byte {
	sha256Tag := sha256.Sum256([]byte(tag))
	data := sha256Tag[:]
	data = append(data, data...)
	data = append(data, x...)
	hash := sha256.Sum256(data)
	return hash[:]
}

// this does lift_x as explained in the bip
func ParsePublicKey(pubkeyBytes []byte) (*secp256k1.PublicKey, error) {
	xcoordinate := new(big.Int).SetBytes(pubkeyBytes)

	if xcoordinate.Cmp(secp256k1.Curve.P) > 0 {
		return nil, errors.New("x is over p")
	}

	c := secp256k1.NewFieldElement(xcoordinate)
	c.Pow(c, big.NewInt(3)).Add(c, secp256k1.Curve.B)

	exponent := new(big.Int).Set(secp256k1.Curve.P)
	exponent.Add(exponent, big.NewInt(1)).Div(exponent, big.NewInt(4)).Mod(exponent, secp256k1.Curve.P)

	y := secp256k1.NewFieldElement(c.Value)
	y.Pow(y, exponent)

	ysquared := secp256k1.NewFieldElement(y.Value)
	ysquared.Pow(ysquared, big.NewInt(2))

	if !ysquared.Equal(c) {
		return nil, errors.New("invalid public key")
	}

	yint := new(big.Int).Set(y.Value)
	mod := new(big.Int).Mod(yint, big.NewInt(2))
	if mod.Cmp(big.NewInt(0)) != 0 {
		ycoordinate := new(big.Int).Set(secp256k1.Curve.P)
		ycoordinate.Sub(ycoordinate, yint)

		y = secp256k1.NewFieldElement(ycoordinate)
	}

	point := &secp256k1.Point{
		X:             secp256k1.NewFieldElement(xcoordinate),
		Y:             y,
		InfinityPoint: false,
	}

	return &secp256k1.PublicKey{point}, nil
}
