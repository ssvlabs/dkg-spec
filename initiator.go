package spec

import (
	"bytes"
	"context"
	"dkg-spec/eip1271"
	"fmt"
	ssz "github.com/ferranbt/fastssz"
	"github.com/google/uuid"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

// RunDKG is called when an initiator wants to start a new DKG ceremony
func RunDKG(init *Init) ([]*Result, error) {
	id := NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/
	_, _, _, err := ValidateResults(
		init.Operators,
		init.WithdrawalCredentials,
		results[0].SignedProof.Proof.ValidatorPubKey,
		init.Fork,
		init.Owner,
		init.Nonce,
		id,
		results)
	return results, err
}

func RunReshare(
	validatorPK []byte,
	withdrawalCredentials []byte,
	fork [4]byte,
	signedReshare *SignedReshare,
	proofs map[*Operator]SignedProof,
	client eip1271.ETHClient,
) ([]*Result, error) {
	if err := VerifySignedMessageByOwner(
		client,
		signedReshare.Reshare.Owner,
		signedReshare,
		signedReshare.Signature); err != nil {
		return nil, err
	}
	id := NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/
	_, _, _, err := ValidateResults(
		signedReshare.Reshare.NewOperators,
		withdrawalCredentials,
		validatorPK,
		fork,
		signedReshare.Reshare.Owner,
		signedReshare.Reshare.Nonce,
		id,
		results)
	return results, err
}

// VerifySignedMessageByOwner returns nil if signature over message is valid (signed by owner)
func VerifySignedMessageByOwner(
	client eip1271.ETHClient,
	owner [20]byte,
	msg ssz.HashRoot,
	signature []byte,
) error {
	isEOASignature, err := IsEOAAccount(client, owner)
	if err != nil {
		return err
	}

	hash, err := msg.HashTreeRoot()
	if err != nil {
		return err
	}

	if isEOASignature {
		pk, err := eth_crypto.SigToPub(hash[:], signature)
		if err != nil {
			return err
		}

		address := eth_crypto.PubkeyToAddress(*pk)

		if common.Address(owner).Cmp(address) != 0 {
			return fmt.Errorf("invalid signed reshare signature")
		}
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
		}, hash[:], signature)
		if err != nil {
			return err
		}
		if !bytes.Equal(eip1271.MagicValue[:], res[:]) {
			return fmt.Errorf("signature invalid")
		}
	}

	return nil
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

// NewID generates a random ID from 2 random concat UUIDs
func NewID() [24]byte {
	var id [24]byte
	b := uuid.New()
	copy(id[:12], b[:])
	b = uuid.New()
	copy(id[12:], b[:])
	return id
}
