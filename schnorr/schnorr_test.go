package schnorr

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/elnosh/secp256k1"
)

// test vectors from BIP-340

func TestSign(t *testing.T) {
	tests := []struct {
		signingKey        string
		auxRand           string
		message           string
		expectedSignature string
	}{
		{
			signingKey:        "0000000000000000000000000000000000000000000000000000000000000003",
			auxRand:           "0000000000000000000000000000000000000000000000000000000000000000",
			message:           "0000000000000000000000000000000000000000000000000000000000000000",
			expectedSignature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
		},
		{
			signingKey:        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
			auxRand:           "0000000000000000000000000000000000000000000000000000000000000001",
			message:           "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			expectedSignature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
		},
		{
			signingKey:        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
			auxRand:           "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
			message:           "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
			expectedSignature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
		},
		{
			signingKey:        "0340034003400340034003400340034003400340034003400340034003400340",
			auxRand:           "0000000000000000000000000000000000000000000000000000000000000000",
			message:           "11",
			expectedSignature: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
		},
		{
			signingKey:        "0340034003400340034003400340034003400340034003400340034003400340",
			auxRand:           "0000000000000000000000000000000000000000000000000000000000000000",
			message:           "0102030405060708090A0B0C0D0E0F1011",
			expectedSignature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
		},
		{
			signingKey:        "0340034003400340034003400340034003400340034003400340034003400340",
			auxRand:           "0000000000000000000000000000000000000000000000000000000000000000",
			message:           "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
			expectedSignature: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
		},
	}

	for _, test := range tests {
		keyInt, _ := new(big.Int).SetString(test.signingKey, 16)
		scalar, _ := secp256k1.NewScalar(keyInt)
		sk := secp256k1.NewPrivateKey(scalar)

		nonceInt, _ := new(big.Int).SetString(test.auxRand, 16)
		nonce, _ := secp256k1.NewScalar(nonceInt)
		nonceKey := secp256k1.NewPrivateKey(nonce)

		message, _ := hex.DecodeString(test.message)

		signature, err := sign(sk, message, nonceKey)
		if err != nil {
			t.Fatalf("error signing: %v", err)
		}

		signatureBytes := bytes.Join([][]byte{signature.r.Bytes(), signature.s.Bytes()}, nil)
		sigHex := strings.ToUpper(hex.EncodeToString(signatureBytes))

		if sigHex != test.expectedSignature {
			t.Fatalf("expected signature '%v' but got '%v'", test.expectedSignature, sigHex)
		}

	}

}

func TestVerify(t *testing.T) {
	//func (s *Signature) Verify(pubkey *secp256k1.PublicKey, hash []byte) bool {

	// tests := []struct {
	// 	signature string
	// 	publicKey string
	// 	message   string
	// 	expected  bool
	// }{
	// 	{
	// 		signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
	// 		publicKey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
	// 		message:   "0000000000000000000000000000000000000000000000000000000000000000",
	// 		expected:  true,
	// 	},
	// 	{
	// 		signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
	// 		publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
	// 		message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
	// 		expected:  true,
	// 	},
	// 	{
	// 		signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
	// 		publicKey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
	// 		message:   "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
	// 		expected:  true,
	// 	},
	// 	{
	// 		signature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
	// 		publicKey: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
	// 		message:   "0102030405060708090A0B0C0D0E0F1011",
	// 		expected:  true,
	// 	},
	// 	{
	// 		signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
	// 		publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
	// 		message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
	// 		expected:  false,
	// 	},
	// 	{
	// 		signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
	// 		publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
	// 		message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
	// 		expected:  false,
	// 	},
	// }

}

// func TestSignAndVerify(t *testing.T) {
// 	privateKey, err := secp256k1.GeneratePrivateKey()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	hash := sha256.Sum256([]byte("hello"))
//
// 	signature, err := Sign(privateKey, hash[:])
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	if !signature.Verify(privateKey.PublicKey, hash[:]) {
// 		t.Fatal("invalid signature")
// 	}
// }