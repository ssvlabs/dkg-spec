package spec

import (
	"bytes"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ssvlabs/dkg-spec/crypto"
)

// ValidateInitMessage returns nil if init message is valid
func ValidateInitMessage(init *Init) error {
	if !UniqueAndOrderedOperators(init.Operators) {
		return fmt.Errorf("operators not unique or not ordered")
	}
	if !ValidThresholdSet(init.T, init.Operators) {
		return fmt.Errorf("threshold set is invalid")
	}
	if !ValidAmountSet(phase0.Gwei(init.Amount)) {
		return fmt.Errorf("amount should be in range between 32 ETH and 2048 ETH")
	}
	return nil
}

// ValidThresholdSet returns true if the number of operators and threshold is valid
func ValidThresholdSet(t uint64, operators []*Operator) bool {
	if len(operators) == 4 && t == 3 { // 2f+1 = 3
		return true
	}
	if len(operators) == 7 && t == 5 { // 2f+1 = 5
		return true
	}
	if len(operators) == 10 && t == 7 { // 2f+1 = 7
		return true
	}
	if len(operators) == 13 && t == 9 { // 2f+1 = 9
		return true
	}
	return false
}

// ThresholdForCluster returns the threshold for provided group, or error
func ThresholdForCluster(operators []*Operator) (uint64, error) {
	if len(operators) == 4 { // 2f+1 = 3
		return 3, nil
	}
	if len(operators) == 7 { // 2f+1 = 5
		return 5, nil
	}
	if len(operators) == 10 { // 2f+1 = 7
		return 7, nil
	}
	if len(operators) == 13 { // 2f+1 = 9
		return 9, nil
	}
	return 0, fmt.Errorf("invalid cluster size")
}

// UniqueAndOrderedOperators returns true if array of operators are unique and ordered (no duplicate IDs)
func UniqueAndOrderedOperators(operators []*Operator) bool {
	highestID := uint64(0)
	for _, op := range operators {
		if op.ID <= highestID {
			return false
		}
		highestID = op.ID
	}
	return true
}

// EqualOperators returns true if both arrays of operators are equal
func EqualOperators(a, b []*Operator) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].PubKey, b[i].PubKey) {
			return false
		}
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

func ValidAmountSet(amount phase0.Gwei) bool {
	if amount >= crypto.MIN_ACTIVATION_BALANCE && amount <= crypto.MAX_EFFECTIVE_BALANCE {
		return true
	}
	return false
}
