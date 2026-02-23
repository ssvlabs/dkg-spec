package testing

import (
	"testing"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/fixtures"

	"github.com/stretchr/testify/require"
)

func TestValidateResign(t *testing.T) {
	crypto.InitBLS()

	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign4Operators,
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign4Operators,
			fixtures.GenerateOperators(4)[1],
			&fixtures.TestOperator2Proof4Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign4Operators,
			fixtures.GenerateOperators(4)[2],
			&fixtures.TestOperator3Proof4Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign4Operators,
			fixtures.GenerateOperators(4)[3],
			&fixtures.TestOperator4Proof4Operators,
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[0],
			&fixtures.TestOperator1Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[1],
			&fixtures.TestOperator2Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[2],
			&fixtures.TestOperator3Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[3],
			&fixtures.TestOperator4Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[4],
			&fixtures.TestOperator5Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[5],
			&fixtures.TestOperator6Proof7Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign7Operators,
			fixtures.GenerateOperators(7)[6],
			&fixtures.TestOperator7Proof7Operators,
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[0],
			&fixtures.TestOperator1Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[1],
			&fixtures.TestOperator2Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[2],
			&fixtures.TestOperator3Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[3],
			&fixtures.TestOperator4Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[4],
			&fixtures.TestOperator5Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[5],
			&fixtures.TestOperator6Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[6],
			&fixtures.TestOperator7Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[7],
			&fixtures.TestOperator8Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[8],
			&fixtures.TestOperator9Proof10Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign10Operators,
			fixtures.GenerateOperators(10)[9],
			&fixtures.TestOperator10Proof10Operators,
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[0],
			&fixtures.TestOperator1Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[1],
			&fixtures.TestOperator2Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[2],
			&fixtures.TestOperator3Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[3],
			&fixtures.TestOperator4Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[4],
			&fixtures.TestOperator5Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[5],
			&fixtures.TestOperator6Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[6],
			&fixtures.TestOperator7Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[7],
			&fixtures.TestOperator8Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[8],
			&fixtures.TestOperator9Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[9],
			&fixtures.TestOperator10Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[10],
			&fixtures.TestOperator11Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[11],
			&fixtures.TestOperator12Proof13Operators,
		))

		require.NoError(t, spec.ValidateResignMessage(
			&fixtures.TestResign13Operators,
			fixtures.GenerateOperators(13)[12],
			&fixtures.TestOperator13Proof13Operators,
		))
	})

	t.Run("add owner address", func(t *testing.T) {
		require.NoError(t, spec.ValidateResignMessage(&spec.Resign{
			ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerNewAddress,
			Nonce:                 0,
			Amount:                uint64(crypto.MAX_EFFECTIVE_BALANCE),
		},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator1Proof4Operators))
	})

	t.Run("invalid proof", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResignMessage(
			&spec.Resign{
				ValidatorPubKey:       fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
				WithdrawalCredentials: fixtures.TestWithdrawalCred,
				Owner:                 fixtures.TestOwnerAddress,
				Nonce:                 1,
				Amount:                uint64(crypto.MIN_ACTIVATION_BALANCE),
			},
			fixtures.GenerateOperators(4)[0],
			&fixtures.TestOperator2Proof4Operators,
		), "crypto/rsa: verification error")
	})

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
