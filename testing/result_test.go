package testing

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/fixtures"

	"github.com/stretchr/testify/require"
)

func TestBuildResult(t *testing.T) {
	t.Run("valid result", func(t *testing.T) {
		result, err := spec.BuildResult(
			1,
			fixtures.TestRequestID,
			fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1),
			fixtures.OperatorSK(fixtures.TestOperator1SK),
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestOwnerAddress,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
		)
		require.NoError(t, err)
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			result,
		))
		decryptedShare, err := spec_crypto.Decrypt(fixtures.OperatorSK(fixtures.TestOperator1SK), result.SignedProof.Proof.EncryptedShare)
		require.NoError(t, err)
		require.EqualValues(t, []byte(fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).SerializeToHexStr()), decryptedShare)
	})
}

func TestValidateResults(t *testing.T) {
	t.Run("valid 3 out of 4 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results4Operators()[:3],
		)
		require.NoError(t, err)
	})

	t.Run("valid 4 out of 4 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results4Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 5 out of 7 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results7Operators()[:5],
		)
		require.NoError(t, err)
	})
	t.Run("valid 6 out of 7 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results7Operators()[:6],
		)
		require.NoError(t, err)
	})
	t.Run("valid 7 out of 7 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results7Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 7 out of 10 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators()[:7],
		)
		require.NoError(t, err)
	})
	t.Run("valid 8 out of 10 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators()[:8],
		)
		require.NoError(t, err)
	})
	t.Run("valid 9 out of 10 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators()[:9],
		)
		require.NoError(t, err)
	})
	t.Run("valid 10 out of 10 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 9 out of 13 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators()[:9],
		)
		require.NoError(t, err)
	})
	t.Run("valid 10 out of 13 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators()[:10],
		)
		require.NoError(t, err)
	})
	t.Run("valid 11 out of 13 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators()[:11],
		)
		require.NoError(t, err)
	})
	t.Run("valid 12 out of 13 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators()[:12],
		)
		require.NoError(t, err)
	})
	t.Run("valid 13 out of 13 operators", func(t *testing.T) {
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("invalid share pub key", func(t *testing.T) {
		res := fixtures.Results4Operators()[:3]
		res = append(res, &spec.Result{
			OperatorID:                 4,
			RequestID:                  fixtures.TestRequestID,
			DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator4DepositSignature4Operators),
			OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator4NonceSignature4Operators),
			SignedProof: spec.SignedProof{
				Proof: &spec.Proof{
					ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
					SharePubKey:     fixtures.ShareSK(fixtures.TestValidator7OperatorsShare1).GetPublicKey().Serialize(),
				},
			},
		})
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		)
		require.EqualError(t, err, "invalid recovered validator pubkey")
	})

	t.Run("too many results", func(t *testing.T) {
		res := fixtures.Results7Operators()
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		)
		require.EqualError(t, err, "mistmatch results count")
	})

	t.Run("too few results", func(t *testing.T) {
		res := fixtures.Results4Operators()
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		)
		require.EqualError(t, err, "mistmatch results count")
	})

	t.Run("invalid result", func(t *testing.T) {
		res := fixtures.Results4Operators()[:3]
		res = append(res, &spec.Result{
			OperatorID:                 1,
			RequestID:                  fixtures.TestRequestID,
			DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
			OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
			SignedProof:                fixtures.TestOperator1Proof4Operators,
		})
		_, _, _, err := spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		)
		require.EqualError(t, err, "failed to recover validator public key from results")
	})
}

func TestValidateResult(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(7),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof7Operators,
			},
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(10),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature10Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature10Operators),
				SignedProof:                fixtures.TestOperator1Proof10Operators,
			},
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(13),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature13Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature13Operators),
				SignedProof:                fixtures.TestOperator1Proof13Operators,
			},
		))
	})

	t.Run("unknown operator", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 5,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "operator not found")
	})

	t.Run("invalid request ID", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  spec.NewID(),
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "invalid request ID")
	})

	t.Run("invalid partial deposit signature", func(t *testing.T) {
		require.ErrorContains(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify deposit partial signatures")
	})

	t.Run("invalid partial nonce signature", func(t *testing.T) {
		require.ErrorContains(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify nonce partial signatures")
	})

	t.Run("invalid proof owner address", func(t *testing.T) {
		require.ErrorContains(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						Owner:           [20]byte{},
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "invalid owner address")
	})

	t.Run("invalid proof signature", func(t *testing.T) {
		require.ErrorContains(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						EncryptedShare:  fixtures.DecodeHexNoError(fixtures.TestValidator4OperatorsShare1),
						Owner:           fixtures.TestOwnerAddress,
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "crypto/rsa: verification error")
	})

	t.Run("invalid validator pubkey", func(t *testing.T) {
		require.ErrorContains(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "invalid proof validator pubkey")
	})
}

func TestPartialNonceRoot(t *testing.T) {
	t.Run("nonce 1", func(t *testing.T) {
		require.EqualValues(t,
			[]byte{0x74, 0x7b, 0x78, 0x3f, 0xcb, 0x76, 0x75, 0xa1, 0xe7, 0xc6, 0xcd, 0x19, 0xa6, 0x0, 0x8, 0x67, 0xf, 0x8b, 0xd3, 0x28, 0xca, 0x87, 0xef, 0x4e, 0xb5, 0x47, 0xfe, 0x7a, 0xc0, 0xfe, 0xdb, 0x4},
			spec.PartialNonceRoot(common.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, 1))
	})

	t.Run("nonce 2", func(t *testing.T) {
		require.EqualValues(t,
			[]byte{0x90, 0x68, 0x19, 0x2a, 0xf8, 0x42, 0x31, 0x85, 0x91, 0xc6, 0x71, 0xe4, 0x3d, 0x2e, 0x99, 0x5b, 0x41, 0x87, 0x15, 0x99, 0xe3, 0xa3, 0x2e, 0xe0, 0xde, 0x88, 0x75, 0xa7, 0xac, 0xaf, 0x8, 0xe},
			spec.PartialNonceRoot(common.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, 2))
	})
}
