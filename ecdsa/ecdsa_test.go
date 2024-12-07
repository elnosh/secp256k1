package ecdsa

import (
	"crypto/sha256"
	"testing"

	"github.com/elnosh/secp256k1"
)

func TestSignAndVerify(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte("hello"))

	signature, err := Sign(privateKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	if !signature.Verify(privateKey.PublicKey, hash[:]) {
		t.Fatal("invalid signature")
	}
}
