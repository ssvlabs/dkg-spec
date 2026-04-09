package eip1271

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

// EIP-1271 magic values (https://eips.ethereum.org/EIPS/eip-1271)
// The four-byte code is defined as follows:
// - 0x00000000 if the signature is invalid.
// - 0x1626ba7e if the signature is valid (standard EIP-1271, selector of isValidSignature(bytes32,bytes)).

// MAGIC_VALUE is the standard EIP-1271 magic value (0x1626ba7e).
var MAGIC_VALUE = [4]byte{0x16, 0x26, 0xba, 0x7e}

var InvalidSigValue = [4]byte{0xff, 0xff, 0xff, 0xff}

type ETHClient interface {
	BlockNumber(ctx context.Context) (uint64, error)
	ChainID(ctx context.Context) (*big.Int, error)
	bind.ContractBackend
}
