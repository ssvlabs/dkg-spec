package spec

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ValidateResignMessage returns nil if re-sign message is valid
func ValidateResignMessage(
	resign *Resign,
	operator *Operator,
	proof *SignedProof,
) error {
	if !ValidAmountSet(phase0.Gwei(resign.Amount)) {
		return fmt.Errorf("amount should be in range between 32 ETH and 2048 ETH")
	}
	if err := ValidateCeremonyProof(resign.Owner, resign.ValidatorPubKey, operator, *proof); err != nil {
		return err
	}

	return nil
}
