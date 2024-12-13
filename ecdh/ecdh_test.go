package ecdh

import (
	"math/big"
	"testing"

	"github.com/elnosh/secp256k1"
)

func TestEcdh(t *testing.T) {

	tests := []struct {
		aliceKey string
		bobKey   string
	}{
		{
			aliceKey: "1111111111111111111111111111111111111111111111111111111111111111",
			bobKey:   "2222222222222222222222222222222222222222222222222222222222222222",
		},
		{
			aliceKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			bobKey:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}

	for _, test := range tests {
		aliceInt, _ := new(big.Int).SetString(test.aliceKey, 16)
		bobInt, _ := new(big.Int).SetString(test.bobKey, 16)

		aliceScalar, _ := secp256k1.NewScalar(aliceInt)
		bobScalar, _ := secp256k1.NewScalar(bobInt)

		aliceKey := secp256k1.NewPrivateKey(aliceScalar)
		bobKey := secp256k1.NewPrivateKey(bobScalar)

		// alice private key * bob public key
		sharedKey1, err := Ecdh(aliceKey, bobKey.PublicKey)
		if err != nil {
			t.Fatalf("error doing ecdh: %v", err)
		}

		// bob private key * alice public key
		sharedKey2, err := Ecdh(bobKey, aliceKey.PublicKey)
		if err != nil {
			t.Fatalf("error doing ecdh: %v", err)
		}

		// derived shared keys should be equal
		if sharedKey1.SecretKey.N.Cmp(sharedKey2.SecretKey.N) != 0 {
			t.Fatalf("derived shared keys do not match. Alice derived shared key '%x' and Bob derived '%x'",
				sharedKey1.SecretKey.N.Bytes(), sharedKey2.SecretKey.N.Bytes())
		}
	}
}
