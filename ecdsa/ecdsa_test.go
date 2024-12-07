package ecdsa

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/elnosh/secp256k1"
)

func TestVerifySignature(t *testing.T) {
	// tests from - github.com/decred/dcrd/dcrec/secp256k1/v4

	x, _ := new(big.Int).SetString("887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c", 16)
	y, _ := new(big.Int).SetString("61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34", 16)
	xelement := secp256k1.NewFieldElement(x)
	yelement := secp256k1.NewFieldElement(y)
	pubkey := &secp256k1.PublicKey{&secp256k1.Point{X: xelement, Y: yelement, InfinityPoint: false}}

	tests := []struct {
		r         string
		s         string
		publicKey *secp256k1.PublicKey
		hash      string
		want      bool
	}{
		{
			r:         "ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
			s:         "68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
			publicKey: pubkey,
			hash:      "ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60",
			want:      true,
		},
		{
			r:         "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
			s:         "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
			publicKey: pubkey,
			hash:      "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
			want:      true,
		},
		{
			r:         "aff69ef2b1bd93a66ed5219add4fb51a29348729587498572498572498457bbb",
			s:         "b7207fee197d27c618aea621406f6bf5ef6fca382398472398742398472398cc",
			publicKey: pubkey,
			hash:      "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
			want:      false,
		},
	}

	for _, test := range tests {
		r, _ := new(big.Int).SetString(test.r, 16)
		s, _ := new(big.Int).SetString(test.s, 16)
		sig := &Signature{r: r, s: s}
		hash, _ := hex.DecodeString(test.hash)

		result := sig.Verify(test.publicKey, hash)
		if result != test.want {
			t.Fatalf("expected '%v' but got '%v'", test.want, result)
		}

	}

}

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
