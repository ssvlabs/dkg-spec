package spec

import (
	"dkg-spec/eip1271"
	"github.com/google/uuid"
	"golang.org/x/exp/maps"
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
		len(init.Operators),
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
		len(signedReshare.Reshare.NewOperators),
		results)
	return results, err
}

func RunResign(
	validatorPK []byte,
	withdrawalCredentials []byte,
	fork [4]byte,
	signedResign *SignedResign,
	proofs map[*Operator]SignedProof,
	client eip1271.ETHClient,
) ([]*Result, error) {
	operators := maps.Keys(proofs)

	t, err := ThresholdForCluster(operators)
	if err != nil {
		return nil, err
	}

	id := NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/

	expectedResultsCount := int(t)
	if len(results) > expectedResultsCount {
		expectedResultsCount = len(results)
	}

	_, _, _, err = ValidateResults(
		operators,
		withdrawalCredentials,
		validatorPK,
		fork,
		signedResign.Resign.Owner,
		signedResign.Resign.Nonce,
		id,
		expectedResultsCount, // resign only requires a threshold of signers
		results)
	return results, err
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
