package crypto

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
)

// VerifySignedMessageByOwner returns nil if signature over message is valid (signed by owner)
func VerifySignedMessageByOwner(
	client eip1271.ETHClient,
	owner [20]byte,
	hash [32]byte,
	signature []byte,
) error {
	isEOASignature, err := IsEOAAccount(client, owner)
	if err != nil {
		return err
	}

	if isEOASignature {
		// EIP 155 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
		if signature[64] == 27 || signature[64] == 28 {
			// v = {0,1} + 27
			signature[64] -= byte(27)
		} else if signature[64] != 0 && signature[64] != 1 {
			chainID, err := client.ChainID(context.Background())
			if err != nil {
				return err
			}
			// v = {0,1} + CHAIN_ID * 2 + 35
			signature[64] -= byte(chainID.Uint64()*2 + 35)
		}

		pk, err := eth_crypto.SigToPub(hash[:], signature)
		if err != nil {
			return err
		}

		address := eth_crypto.PubkeyToAddress(*pk)

		if common.Address(owner).Cmp(address) == 0 {
			return nil
		}
		return fmt.Errorf("invalid EOA signature")
	} else {
		// EIP 1271 signature
		// gnosis implementation https://github.com/safe-global/safe-smart-account/blob/2278f7ccd502878feb5cec21dd6255b82df374b5/contracts/Safe.sol#L265
		// https://github.com/safe-global/safe-smart-account/blob/main/docs/signatures.md
		// ... verify via contract call
		signerVerification, err := eip1271.NewEip1271(owner, client)
		if err != nil {
			return err
		}
		res, err := signerVerification.IsValidSignature(&bind.CallOpts{
			Context: context.Background(),
		}, hash, signature)
		if err != nil {
			return err
		}
		if bytes.Equal(eip1271.MAGIC_VALUE_PERSONAL_SIGN[:], res[:]) || bytes.Equal(eip1271.MAGIC_VALUE_ETH_SIGN[:], res[:]) {
			return nil
		}
		return fmt.Errorf("invalid eip1271 signature")
	}
}

func IsEOAAccount(client eip1271.ETHClient, address common.Address) (bool, error) {
	block, err := client.BlockNumber(context.Background())
	if err != nil {
		return false, err
	}

	code, err := client.CodeAt(context.Background(), address, (&big.Int{}).SetUint64(block))
	if err != nil {
		return false, err
	}
	return len(code) == 0, nil
}
