package spec

import (
	"crypto/rsa"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
)

// Init is called on operator side when a new init message is received from initiator
func (op *Operator) Init(
	init *Init,
	requestID [24]byte,
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
		phase0.Gwei(init.Amount),
	)
	if err != nil {
		return nil, err
	}
	depositDataSig := share.SignByte(depositDataRoot[:])

	// sign proof
	encryptedShare, err := crypto.Encrypt(&sk.PublicKey, []byte(share.SerializeToHexStr()))
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
		OperatorID:                 op.ID,
		RequestID:                  requestID,
		DepositPartialSignature:    depositDataSig.Serialize(),
		OwnerNoncePartialSignature: share.SignByte(PartialNonceRoot(init.Owner, init.Nonce)).Serialize(),
		SignedProof: SignedProof{
			Proof:     proof,
			Signature: proofSig,
		},
	}, nil
}

// Reshare is called when an operator receives a reshare message
func (op *Operator) Reshare(
	signedReshare *SignedReshare,
	proof *SignedProof,
	requestID [24]byte,
	sk *rsa.PrivateKey,
	client eip1271.ETHClient,
) (*Result, error) {
	hash, err := signedReshare.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	if err := crypto.VerifySignedMessageByOwner(
		client,
		signedReshare.Reshare.Owner,
		hash,
		signedReshare.Signature,
	); err != nil {
		return nil, err
	}
	if err := ValidateReshareMessage(&signedReshare.Reshare, op, proof); err != nil {
		return nil, err
	}

	var share *bls.SecretKey
	/*
		reshare ceremony
		All new participants must participate
		T out of old participants must participate
	*/

	return BuildResult(
		op.ID,
		requestID,
		share,
		sk,
		signedReshare.Reshare.ValidatorPubKey,
		signedReshare.Reshare.Owner,
		signedReshare.Reshare.WithdrawalCredentials,
		signedReshare.Reshare.Fork,
		signedReshare.Reshare.Nonce,
		phase0.Gwei(signedReshare.Reshare.Amount),
	)
}

// Resign is called when an operator receives a re-sign message
func (op *Operator) Resign(
	signedResign *SignedResign,
	proof *SignedProof,
	requestID [24]byte,
	share *bls.SecretKey,
	sk *rsa.PrivateKey, // operator's encryption private key
	client eip1271.ETHClient,
) (*Result, error) {
	hash, err := signedResign.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	if err := crypto.VerifySignedMessageByOwner(
		client,
		signedResign.Resign.Owner,
		hash,
		signedResign.Signature,
	); err != nil {
		return nil, err
	}
	if err := ValidateResignMessage(&signedResign.Resign, op, proof); err != nil {
		return nil, err
	}

	return BuildResult(
		op.ID,
		requestID,
		share,
		sk,
		signedResign.Resign.ValidatorPubKey,
		signedResign.Resign.Owner,
		signedResign.Resign.WithdrawalCredentials,
		signedResign.Resign.Fork,
		signedResign.Resign.Nonce,
		phase0.Gwei(signedResign.Resign.Amount),
	)
}
