package spec

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ValidateReshareMessage returns nil if re-share message is valid
func ValidateReshareMessage(
	reshare *Reshare,
	operator *Operator,
	proof *SignedProof,
) error {
	if !UniqueAndOrderedOperators(reshare.OldOperators) {
		return fmt.Errorf("old operators are not unique and ordered")
	}

	if err := ValidateCeremonyProof(reshare.ValidatorPubKey, operator, *proof); err != nil {
		return err
	}
	// verify owner address
	if !bytes.Equal(reshare.Owner[:], proof.Proof.Owner[:]) {
		return fmt.Errorf("invalid owner address")
	}

	if !UniqueAndOrderedOperators(reshare.NewOperators) {
		return fmt.Errorf("new operators are not unique and ordered")
	}
	if EqualOperators(reshare.OldOperators, reshare.NewOperators) {
		return fmt.Errorf("old and new operators are the same")
	}
	if !ValidThresholdSet(reshare.OldT, reshare.OldOperators) {
		return fmt.Errorf("old threshold set is invalid")
	}
	if !ValidThresholdSet(reshare.NewT, reshare.NewOperators) {
		return fmt.Errorf("new threshold set is invalid")
	}
	if !ValidAmountSet(phase0.Gwei(reshare.Amount)) {
		return fmt.Errorf("amount should be in range between 32 ETH and 2048 ETH")
	}
	return nil
}

func OrderOperators(in []*Operator) []*Operator {
	sort.Slice(in, func(i, j int) bool {
		return in[i].ID < in[j].ID
	})
	return in
}
