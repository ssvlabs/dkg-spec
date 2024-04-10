package crypto

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
	"testing"
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
			PublicKey:             phase0.BLSPubKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
		})
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{211, 144, 58, 131, 8, 179, 69, 74, 17, 237, 153, 158, 78, 44, 172, 234, 232, 39, 24, 173, 42, 18, 85, 227, 114, 63, 250, 196, 225, 17, 32, 43})
	})

	t.Run("holesky", func(t *testing.T) {
		r, err := ComputeDepositMessageSigningRoot(core.HoleskyNetwork, &phase0.DepositMessage{
			PublicKey:             phase0.BLSPubKey{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			WithdrawalCredentials: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			Amount:                32000000000,
		})
		require.NoError(t, err)
		require.EqualValues(t, r, phase0.Root{111, 233, 230, 111, 196, 39, 220, 136, 221, 175, 70, 138, 111, 71, 122, 69, 253, 137, 184, 240, 13, 124, 138, 43, 88, 250, 240, 100, 95, 162, 232, 111})
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
