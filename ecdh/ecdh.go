package ecdh

import (
	"crypto/sha256"
	"math/big"

	"github.com/elnosh/secp256k1"
)

func Ecdh(privateKey *secp256k1.PrivateKey, publicKey *secp256k1.PublicKey) (*secp256k1.PrivateKey, error) {
	scalar, err := secp256k1.NewScalar(privateKey.SecretKey.N)
	if err != nil {
		return nil, err
	}

	publicKeyPoint := publicKey.Point.Copy()

	sharedPoint := secp256k1.ScalarMult(scalar, publicKeyPoint)

	// compute shared secret key by hashing x-coordinate of shared point
	hash := sha256.Sum256(sharedPoint.X.Value.Bytes())

	bigint := new(big.Int).SetBytes(hash[:])
	sharedScalar, err := secp256k1.NewScalar(bigint)
	if err != nil {
		return nil, err
	}

	sharedKey := secp256k1.NewPrivateKey(sharedScalar)
	return sharedKey, nil
}
