package secp256k1

import "math/big"

var (
	p *big.Int
)

func init() {
	p = new(big.Int)
	p.SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
}
