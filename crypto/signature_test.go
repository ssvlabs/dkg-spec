package crypto

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	ssz "github.com/ferranbt/fastssz"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
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
			hash,
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
			hash,
			sig), "invalid EOA signature")
	})

	t.Run("valid contract signature", func(t *testing.T) {
		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.MAGIC_VALUE[:])

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
			hash,
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
			hash,
			sig), "invalid eip1271 signature")
	})
}

func TestVerifyMultisigSigned3of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")

		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)
		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
		finalMsg = append(finalMsg, message...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		// 3 sigs concatenated
		encSigs, err := hex.DecodeString("e6cca66b0ce03f8049347ad9d8252f034fd538be62ddb4fc01dedccd723c7567050f8882aab359d9f5c13938ae8fa3a7109f4f5005630ef829b4683b7221377f1c6ef175759ce0e1890cdd57576e0216be371d528dfce7a27b1b843b12e49feed907d909ac1dfbd237499b8b504a8ea0ebce850987331cc56c208dc90c9c9d89601c7456f55438bfa68016e710e5053a4a7fb0e4108af09c29f9f43bd21c315bba9616ac391f74b3f3e931e4c358b2058c028296d0b364bd43065d47ba72761663aa1c")
		require.NoError(t, err)
		require.NoError(t, VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			encSigs))
	})
}

func TestVerifyMultisigSigned2of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")

		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)
		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
		finalMsg = append(finalMsg, message...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		// 2 sigs concatenated
		encSigs, err := hex.DecodeString("e6cca66b0ce03f8049347ad9d8252f034fd538be62ddb4fc01dedccd723c7567050f8882aab359d9f5c13938ae8fa3a7109f4f5005630ef829b4683b7221377f1c6ef175759ce0e1890cdd57576e0216be371d528dfce7a27b1b843b12e49feed907d909ac1dfbd237499b8b504a8ea0ebce850987331cc56c208dc90c9c9d89601c")
		require.NoError(t, err)
		require.NoError(t, VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			encSigs))
	})
}

func TestVerifyMultisigSigned1of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")

		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)
		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
		finalMsg = append(finalMsg, message...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		// 1 sig - les than threshold
		encSigs, err := hex.DecodeString("e6cca66b0ce03f8049347ad9d8252f034fd538be62ddb4fc01dedccd723c7567050f8882aab359d9f5c13938ae8fa3a7109f4f5005630ef829b4683b7221377f1c")
		require.NoError(t, err)
		require.ErrorContains(t, VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			encSigs), "GS020")
	})
}
