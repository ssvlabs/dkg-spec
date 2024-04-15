package spec

import (
	"crypto/rsa"

	"github.com/bloxapp/dkg-spec/crypto"
	"github.com/bloxapp/dkg-spec/eip1271"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// OperatorInit is called on operator side when a new init message is received from initiator
func OperatorInit(
	init *Init,
	requestID [24]byte,
	operatorID uint64,
	sk *rsa.PrivateKey,
) (*Result, error) {
	if err := ValidateInitMessage(init); err != nil {
		return nil, err
	}

	var share *bls.SecretKey
	var validatorPK []byte
	/*
		DKG ceremony
		ALL participants must participate
	*/

	// sign deposit data
	depositDataRoot, err := crypto.DepositDataRootForFork(
		init.Fork,
		validatorPK,
		init.WithdrawalCredentials,
		crypto.MaxEffectiveBalanceInGwei,
	)
	if err != nil {
		return nil, err
	}
	depositDataSig := share.SignByte(depositDataRoot[:])

	// sign proof
	encryptedShare, err := crypto.Encrypt(&sk.PublicKey, share.Serialize())
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  encryptedShare,
		SharePubKey:     share.GetPublicKey().Serialize(),
		Owner:           init.Owner,
	}
	byts, err := proof.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	proofSig, err := crypto.SignRSA(sk, byts)
	if err != nil {
		return nil, err
	}

	return &Result{
		OperatorID:                 operatorID,
		RequestID:                  requestID,
		DepositPartialSignature:    depositDataSig.Serialize(),
		OwnerNoncePartialSignature: share.SignByte(PartialNonceRoot(init.Owner, init.Nonce)).Serialize(),
		SignedProof: SignedProof{
			Proof:     proof,
			Signature: proofSig,
		},
	}, nil
}

// OperatorReshare is called when an operator receives a reshare message
func OperatorReshare(
	signedReshare *SignedReshare,
	operator *Operator,
	proof *SignedProof,
	requestID [24]byte,
	sk *rsa.PrivateKey,
	client eip1271.ETHClient,
) (*Result, error) {
	if err := VerifySignedMessageByOwner(
		client,
		signedReshare.Reshare.Owner,
		signedReshare,
		signedReshare.Signature,
	); err != nil {
		return nil, err
	}
	if err := ValidateReshareMessage(&signedReshare.Reshare, operator, proof); err != nil {
		return nil, err
	}

	var share *bls.SecretKey
	/*
		reshare ceremony
		All new participants must participate
		T out of old participants must participate
	*/

	return BuildResult(
		operator.ID,
		requestID,
		share,
		sk,
		signedReshare.Reshare.ValidatorPubKey,
		signedReshare.Reshare.Owner,
		signedReshare.Reshare.WithdrawalCredentials,
		signedReshare.Reshare.Fork,
		signedReshare.Reshare.Nonce,
	)
}

// OperatorResign is called when an operator receives a re-sign message
func OperatorResign(
	signedResign *SignedResign,
	operator *Operator,
	proof *SignedProof,
	requestID [24]byte,
	share *bls.SecretKey,
	sk *rsa.PrivateKey,
	client eip1271.ETHClient,
) (*Result, error) {
	if err := VerifySignedMessageByOwner(
		client,
		signedResign.Resign.Owner,
		signedResign,
		signedResign.Signature,
	); err != nil {
		return nil, err
	}
	if err := ValidateResignMessage(&signedResign.Resign, operator, proof); err != nil {
		return nil, err
	}

	return BuildResult(
		operator.ID,
		requestID,
		share,
		sk,
		signedResign.Resign.ValidatorPubKey,
		signedResign.Resign.Owner,
		signedResign.Resign.WithdrawalCredentials,
		signedResign.Resign.Fork,
		signedResign.Resign.Nonce,
	)
}

func BuildResult(
	operatorID uint64,
	requestID [24]byte,
	share *bls.SecretKey,
	sk *rsa.PrivateKey,
	validatorPK []byte,
	owner [20]byte,
	withdrawalCredentials []byte,
	fork [4]byte,
	nonce uint64,
) (*Result, error) {
	// sign deposit data
	depositDataRoot, err := crypto.DepositDataRootForFork(
		fork,
		validatorPK,
		withdrawalCredentials,
		crypto.MaxEffectiveBalanceInGwei,
	)
	if err != nil {
		return nil, err
	}
	depositDataSig := share.SignByte(depositDataRoot[:])

	// sign proof
	encryptedShare, err := crypto.Encrypt(&sk.PublicKey, share.Serialize())
	if err != nil {
		return nil, err
	}
	newProof := &Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  encryptedShare,
		SharePubKey:     share.GetPublicKey().Serialize(),
		Owner:           owner,
	}
	byts, err := newProof.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	proofSig, err := crypto.SignRSA(sk, byts)
	if err != nil {
		return nil, err
	}

	return &Result{
		OperatorID:                 operatorID,
		RequestID:                  requestID,
		DepositPartialSignature:    depositDataSig.Serialize(),
		OwnerNoncePartialSignature: share.SignByte(PartialNonceRoot(owner, nonce)).Serialize(),
		SignedProof: SignedProof{
			Proof:     newProof,
			Signature: proofSig,
		},
	}, nil
}
