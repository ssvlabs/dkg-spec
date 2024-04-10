package testing

import (
	spec "dkg-spec"
	"dkg-spec/eip1271"
	"dkg-spec/testing/fixtures"
	"dkg-spec/testing/stubs"
	"github.com/ethereum/go-ethereum"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestVerifySignedReshare(t *testing.T) {
	t.Run("valid EOA signature", func(t *testing.T) {
		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}

		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		reshare := spec.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, spec.VerifySignedMessageByOwner(stubClient,
			address,
			&reshare,
			sig,
		))
	})

	t.Run("invalid EOA signature", func(t *testing.T) {
		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}

		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)

		reshare := spec.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           fixtures.TestOwnerAddress,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, spec.VerifySignedMessageByOwner(stubClient,
			fixtures.TestOwnerAddress,
			&reshare,
			sig), "invalid signed reshare signature")
	})

	t.Run("valid contract signature", func(t *testing.T) {
		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.MagicValue[:])

				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				address: true,
			},
		}

		reshare := spec.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, spec.VerifySignedMessageByOwner(stubClient,
			address,
			&reshare,
			sig))
	})

	t.Run("invalid contract signature", func(t *testing.T) {
		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.InvalidSigValue[:])

				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				address: true,
			},
		}

		reshare := spec.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, spec.VerifySignedMessageByOwner(stubClient,
			address,
			&reshare,
			sig), "signature invalid")
	})
}
