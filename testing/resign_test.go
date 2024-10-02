package testing

import (
	"testing"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/fixtures"
	"github.com/stretchr/testify/require"
)

func TestValidateResignMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(&spec.Resign{
			ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
			Amount:                uint64(crypto.MIN_ACTIVATION_BALANCE),
		},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators))
	})
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(&spec.Resign{
			ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
			Amount:                uint64(crypto.MAX_EFFECTIVE_BALANCE),
		},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators))
	})
	t.Run("amount < 32 ETH", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResignMessage(&spec.Resign{
			ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
			Amount:                uint64(crypto.MIN_ACTIVATION_BALANCE - 1),
		},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators),
			"amount should be in range between 32 ETH and 2048 ETH")
	})
	t.Run("amount > 2048 ETH", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResignMessage(&spec.Resign{
			ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
			Amount:                uint64(crypto.MAX_EFFECTIVE_BALANCE + 1),
		},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators),
			"amount should be in range between 32 ETH and 2048 ETH")
	})
}
