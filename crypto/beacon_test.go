package crypto

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/ssvlabs/eth2-key-manager/core"
	"github.com/stretchr/testify/require"
)

func TestETH1WithdrawalCredentials(t *testing.T) {
	t.Run("eth1 withdrawal cred from string", func(t *testing.T) {
		eth1Address := common.HexToAddress("d999bc994e0274235b65ca72ec430b8de3eb7df9")
		require.EqualValues(t, ETH1WithdrawalCredentials(eth1Address[:]), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xd9, 0x99, 0xbc, 0x99, 0x4e, 0x2, 0x74, 0x23, 0x5b, 0x65, 0xca, 0x72, 0xec, 0x43, 0xb, 0x8d, 0xe3, 0xeb, 0x7d, 0xf9})
	})

	t.Run("eth1 withdrawal cred from bytes", func(t *testing.T) {
		eth1Address := common.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		require.EqualValues(t, ETH1WithdrawalCredentials(eth1Address[:]), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	})
}

func TestComputeDepositMessageSigningRoot(t *testing.T) {
	t.Run("mainnet", func(t *testing.T) {
		r, err := ComputeDepositMessageSigningRoot(core.MainNetwork, &phase0.DepositMessage{
			PublicKey:             phase0.BLSPubKey([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			WithdrawalCredentials: ETH1WithdrawalCredentials([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
			Amount:                32000000000,
		})
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{65, 251, 162, 3, 213, 126, 91, 235, 147, 143, 240, 158, 49, 73, 43, 224, 197, 115, 203, 211, 216, 164, 112, 192, 1, 34, 88, 168, 155, 185, 59, 156})
	})

	t.Run("holesky", func(t *testing.T) {
		r, err := ComputeDepositMessageSigningRoot(core.HoleskyNetwork, &phase0.DepositMessage{
			PublicKey:             phase0.BLSPubKey([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			WithdrawalCredentials: ETH1WithdrawalCredentials([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
			Amount:                32000000000,
		})
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{69, 0, 246, 46, 94, 170, 246, 64, 34, 97, 251, 181, 210, 250, 187, 64, 43, 220, 229, 196, 72, 92, 164, 213, 123, 170, 99, 7, 22, 67, 87, 55})
	})
}

func TestDepositDataRootForFork(t *testing.T) {
	t.Run("mainnet", func(t *testing.T) {
		r, err := DepositDataRootForFork(
			phase0.Version{0, 0, 0, 0},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			32000000000,
		)
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{65, 251, 162, 3, 213, 126, 91, 235, 147, 143, 240, 158, 49, 73, 43, 224, 197, 115, 203, 211, 216, 164, 112, 192, 1, 34, 88, 168, 155, 185, 59, 156})
	})

	t.Run("holesky", func(t *testing.T) {
		r, err := DepositDataRootForFork(
			phase0.Version{0x01, 0x01, 0x70, 0x00},
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			32000000000,
		)
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{69, 0, 246, 46, 94, 170, 246, 64, 34, 97, 251, 181, 210, 250, 187, 64, 43, 220, 229, 196, 72, 92, 164, 213, 123, 170, 99, 7, 22, 67, 87, 55})
	})
}

func TestVerifyDepositData(t *testing.T) {
	t.Run("mainnet", func(t *testing.T) {
		InitBLS()
		sk := &bls.SecretKey{}
		require.NoError(t, sk.SetHexString("11e35da0958187d89cd6f7cc2b07a0a3f6225ad1e2b089d12e9b08f7f171c1c9"))

		pk := phase0.BLSPubKey{}
		copy(pk[:], sk.GetPublicKey().Serialize())

		r, err := ComputeDepositMessageSigningRoot(core.MainNetwork, &phase0.DepositMessage{
			PublicKey:             pk,
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
		})
		require.NoError(t, err)

		sig := phase0.BLSSignature{}
		copy(sig[:], sk.SignByte(r[:]).Serialize())

		depositData := &phase0.DepositData{
			PublicKey:             pk,
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
			Signature:             sig,
		}

		require.NoError(t, VerifyDepositData(core.MainNetwork, depositData))
	})

	t.Run("holesky", func(t *testing.T) {
		InitBLS()
		sk := &bls.SecretKey{}
		require.NoError(t, sk.SetHexString("11e35da0958187d89cd6f7cc2b07a0a3f6225ad1e2b089d12e9b08f7f171c1c9"))

		pk := phase0.BLSPubKey{}
		copy(pk[:], sk.GetPublicKey().Serialize())

		r, err := ComputeDepositMessageSigningRoot(core.HoleskyNetwork, &phase0.DepositMessage{
			PublicKey:             pk,
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
		})
		require.NoError(t, err)

		sig := phase0.BLSSignature{}
		copy(sig[:], sk.SignByte(r[:]).Serialize())

		depositData := &phase0.DepositData{
			PublicKey:             pk,
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
			Signature:             sig,
		}

		require.NoError(t, VerifyDepositData(core.HoleskyNetwork, depositData))
	})
}
