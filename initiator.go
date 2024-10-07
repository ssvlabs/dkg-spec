package spec

import (
	"fmt"

	eth_crypto "github.com/ethereum/go-ethereum/crypto"
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
			id,
			results[i])
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func GetBulkMessageHash(bulkMsg []SSZMarshaller) ([32]byte, error) {
	hash := [32]byte{}
	msgBytes := []byte{}
	for _, resign := range bulkMsg {
		resignBytes, err := resign.MarshalSSZ()
		if err != nil {
			return hash, err
		}
		msgBytes = append(msgBytes, resignBytes...)
	}
	copy(hash[:], eth_crypto.Keccak256(msgBytes))
	return hash, nil
}

func GetReqIDFromMsg(instance SSZMarshaller) ([24]byte, error) {
	// make a unique ID for each reshare using the instance hash
	reqID := [24]byte{}
	msgBytes, err := instance.MarshalSSZ()
	if err != nil {
		return reqID, err
	}
	copy(reqID[:], eth_crypto.Keccak256(msgBytes))
	return reqID, nil
}
