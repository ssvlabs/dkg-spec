package spec

// ValidateResignMessage returns nil if re-sign message is valid
func ValidateResignMessage(
	resign *Resign,
	proofs map[*Operator]SignedProof,
) error {
	for operator, proof := range proofs {
		if err := ValidateCeremonyProof(resign.Owner, resign.ValidatorPubKey, operator, proof); err != nil {
			return err
		}
	}

	return nil
}
