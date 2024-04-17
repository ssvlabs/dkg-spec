package testing

import (
	"testing"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/testing/fixtures"

	"github.com/stretchr/testify/require"
)

func TestThresholdForCluster(t *testing.T) {
	t.Run("cluster size 4", func(t *testing.T) {
		threshold, err := spec.ThresholdForCluster(fixtures.GenerateOperators(4))
		require.NoError(t, err)
		require.EqualValues(t, 3, threshold)
	})
	t.Run("cluster size 7", func(t *testing.T) {
		threshold, err := spec.ThresholdForCluster(fixtures.GenerateOperators(7))
		require.NoError(t, err)
		require.EqualValues(t, 5, threshold)
	})
	t.Run("cluster size 10", func(t *testing.T) {
		threshold, err := spec.ThresholdForCluster(fixtures.GenerateOperators(10))
		require.NoError(t, err)
		require.EqualValues(t, 7, threshold)
	})
	t.Run("cluster size 13", func(t *testing.T) {
		threshold, err := spec.ThresholdForCluster(fixtures.GenerateOperators(13))
		require.NoError(t, err)
		require.EqualValues(t, 9, threshold)
	})
}

func TestValidateInitMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             fixtures.GenerateOperators(4),
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}))
	})

	t.Run("disordered operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				fixtures.GenerateOperators(4)[0],
				fixtures.GenerateOperators(4)[1],
				fixtures.GenerateOperators(4)[3],
				fixtures.GenerateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "operators not unique or not ordered")
	})
	t.Run("non unique operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				fixtures.GenerateOperators(4)[0],
				fixtures.GenerateOperators(4)[1],
				fixtures.GenerateOperators(4)[2],
				fixtures.GenerateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "operators not unique or not ordered")
	})
	t.Run("no operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             []*spec.Operator{},
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("nil operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             nil,
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 3f+1 operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				fixtures.GenerateOperators(4)[0],
				fixtures.GenerateOperators(4)[1],
				fixtures.GenerateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 3f+1 operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				fixtures.GenerateOperators(7)[0],
				fixtures.GenerateOperators(7)[1],
				fixtures.GenerateOperators(7)[2],
				fixtures.GenerateOperators(7)[3],
				fixtures.GenerateOperators(7)[4],
			},
			T:                     3,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 2f+1 threshold", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             fixtures.GenerateOperators(4),
			T:                     2,
			WithdrawalCredentials: fixtures.TestWithdrawalCred,
			Fork:                  fixtures.TestFork,
			Owner:                 fixtures.TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
}
