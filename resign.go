package spec

// ValidateResignMessage returns nil if re-sign message is valid
func ValidateResignMessage(
	resign *Resign,
	operator *Operator,
	proof *SignedProof,
) error {
	if err := ValidateCeremonyProof(resign.Owner, resign.ValidatorPubKey, operator, *proof); err != nil {
		return err
	}

	return nil
}
