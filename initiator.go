package spec

import (
<<<<<<< HEAD
	"fmt"
=======
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ssvlabs/dkg-spec/eip1271"

	"github.com/google/uuid"
	"golang.org/x/exp/maps"
>>>>>>> master
)

// RunDKG is called when an initiator wants to start a new DKG ceremony
func RunDKG(init *Init) ([]*Result, error) {
	id, err := GetReqIDFromMsg(init)
	if err != nil {
		return nil, fmt.Errorf("failed to get reqID: %w", err)
	}

	var results []*Result
	/*
		DKG ceremony ...
	*/
	_, _, _, err = ValidateResults(
		init.Operators,
		init.WithdrawalCredentials,
		results[0].SignedProof.Proof.ValidatorPubKey,
		init.Fork,
		init.Owner,
		init.Nonce,
		phase0.Gwei(init.Amount),
		id,
		results)
	return results, err
}

func RunReshare(signedReshare *SignedReshare) ([][]*Result, error) {
	id, err := GetReqIDFromMsg(signedReshare)
	if err != nil {
		return nil, fmt.Errorf("failed to get reqID: %w", err)
	}

	var results [][]*Result
	/*
		reshare ceremonies ...
	*/
	for i, reshareMsg := range signedReshare.Messages {
		_, _, _, err := ValidateResults(
			reshareMsg.Reshare.NewOperators,
			reshareMsg.Reshare.WithdrawalCredentials,
			reshareMsg.Reshare.ValidatorPubKey,
			reshareMsg.Reshare.Fork,
			reshareMsg.Reshare.Owner,
			reshareMsg.Reshare.Nonce,
			phase0.Gwei(reshareMsg.Reshare.Amount),
			id,
			results[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func RunResign(signedResign *SignedResign) ([][]*Result, error) {
	id, err := GetReqIDFromMsg(signedResign)
	if err != nil {
		return nil, fmt.Errorf("failed to get reqID: %w", err)
	}

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
			phase0.Gwei(resignMsg.Resign.Amount),
			id,
			results[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}
