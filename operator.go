package spec

import (
	"crypto/rsa"
	"dkg-spec/crypto"
	"dkg-spec/eip1271"
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
	proofs map[*Operator]SignedProof,
	requestID [24]byte,
	operatorID uint64,
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
	if err := ValidateReshareMessage(&signedReshare.Reshare, proofs); err != nil {
		return nil, err
	}

	var share *bls.SecretKey
	/*
		reshare ceremony
		All new participants must participate
		T out of old participants must participate
	*/

	// sign deposit data
	depositDataRoot, err := crypto.DepositDataRootForFork(
		signedReshare.Reshare.Fork,
		signedReshare.Reshare.ValidatorPubKey,
		signedReshare.Reshare.WithdrawalCredentials,
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
		ValidatorPubKey: signedReshare.Reshare.ValidatorPubKey,
		EncryptedShare:  encryptedShare,
		SharePubKey:     share.GetPublicKey().Serialize(),
		Owner:           signedReshare.Reshare.Owner,
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
		OwnerNoncePartialSignature: share.SignByte(PartialNonceRoot(signedReshare.Reshare.Owner, signedReshare.Reshare.Nonce)).Serialize(),
		SignedProof: SignedProof{
			Proof:     proof,
			Signature: proofSig,
		},
	}, nil
}

// OperatorResign is called when an operator receives a resign message
func OperatorResign(
	signedResign *SignedResign,
	proofs map[*Operator]SignedProof,
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
	if err := ValidateResignMessage(&signedResign.Resign, proofs); err != nil {
		return nil, err
	}

	return nil, nil
}
