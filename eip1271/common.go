package eip1271

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

// EIP-1271 magic values (https://eips.ethereum.org/EIPS/eip-1271)
// The four-byte code is defined as follows:
// - 0x00000000 if the signature is invalid.
// - 0x20c13b0b if the signature is valid and was produced using the eth_sign method.
// - 0x1626ba7e if the signature is valid and was produced using the personal_sign method.

var MAGIC_VALUE_ETH_SIGN = [4]byte{0x16, 0x26, 0xba, 0x7e}
var MAGIC_VALUE_PERSONAL_SIGN = [4]byte{0x20, 0xc1, 0x3b, 0x0b}
var InvalidSigValue = [4]byte{0xff, 0xff, 0xff, 0xff}

type ETHClient interface {
	BlockNumber(ctx context.Context) (uint64, error)
	NetworkID(ctx context.Context) (*big.Int, error)
	bind.ContractBackend
}
