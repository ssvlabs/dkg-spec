package fixtures

import (
	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/crypto"
)

var (
	TestResign4Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
		Amount:          uint64(crypto.MIN_ACTIVATION_BALANCE),
	}
	TestResign7Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
		Amount:          uint64(crypto.MIN_ACTIVATION_BALANCE),
	}
	TestResign10Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
		Amount:          uint64(crypto.MIN_ACTIVATION_BALANCE),
	}
	TestResign13Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
		Amount:          uint64(crypto.MIN_ACTIVATION_BALANCE),
	}
)
