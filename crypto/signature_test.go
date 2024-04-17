package crypto

import (
	"testing"

	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"

	"github.com/ethereum/go-ethereum"
	ssz "github.com/ferranbt/fastssz"

	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// SSZBytes --
type SSZBytes []byte

func (b SSZBytes) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

func (b SSZBytes) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}

func (b SSZBytes) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutBytes(b)
	hh.Merkleize(indx)
	return nil
}

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

		plain := SSZBytes("testing vector")
		hash, err := plain.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, VerifySignedMessageByOwner(stubClient,
			address,
			plain,
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

		plain := SSZBytes("testing vector")
		hash, err := plain.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, VerifySignedMessageByOwner(stubClient,
			[20]byte{},
			plain,
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

		plain := SSZBytes("testing vector")
		hash, err := plain.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, VerifySignedMessageByOwner(stubClient,
			address,
			plain,
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

		plain := SSZBytes("testing vector")
		hash, err := plain.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, VerifySignedMessageByOwner(stubClient,
			address,
			plain,
			sig), "signature invalid")
	})
}
