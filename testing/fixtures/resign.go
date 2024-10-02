package fixtures

import spec "github.com/ssvlabs/dkg-spec"

var (
	TestResign4Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
	}
	TestResign7Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
	}
	TestResign10Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
	}
	TestResign13Operators = spec.Resign{
		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
		Nonce:           1,
	}
)
