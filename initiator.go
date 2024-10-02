package spec

import (
	"github.com/google/uuid"
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

func RunReshare(signedReshare *SignedReshare) ([][]*Result, error) {
	id := NewID()

	var results [][]*Result
	/*
		DKG ceremony ...
	*/
	for i, reshareMsg := range signedReshare.Messages {
		_, _, _, err := ValidateResults(
			reshareMsg.Reshare.NewOperators,
			reshareMsg.Reshare.WithdrawalCredentials,
			reshareMsg.Reshare.ValidatorPubKey,
			reshareMsg.Reshare.Fork,
			reshareMsg.Reshare.Owner,
			reshareMsg.Reshare.Nonce,
			id,
			results[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func RunResign(signedResign *SignedResign) ([][]*Result, error) {
	id := NewID()

	var results [][]*Result
	/*
		DKG ceremony ...
	*/

	for i, resignMsg := range signedResign.Messages {
		_, _, _, err := ValidateResults(
			resignMsg.Operators,
			resignMsg.Resign.WithdrawalCredentials,
			resignMsg.Resign.ValidatorPubKey,
			resignMsg.Resign.Fork,
			resignMsg.Resign.Owner,
			resignMsg.Resign.Nonce,
			id,
			results[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
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
