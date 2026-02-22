package spec

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/ssvlabs/dkg-spec/crypto"
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
	if err := crypto.ValidateWithdrawalCredentials(resign.WithdrawalCredentials); err != nil {
		return fmt.Errorf("invalid withdrawal credentials: %w", err)
	}
	if err := ValidateCeremonyProof(resign.ValidatorPubKey, operator, *proof); err != nil {
		return err
	}
	return nil
}
