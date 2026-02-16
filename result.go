package spec

import (
	"bytes"
	"crypto/rsa"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/eth2-key-manager/core"
)

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
	amount phase0.Gwei,
) (*Result, error) {
	// sign deposit data
	depositDataRoot, err := crypto.DepositDataRootForFork(
		fork,
		validatorPK,
		withdrawalCredentials,
		phase0.Gwei(amount),
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
	newProof := &Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  encryptedShare,
		SharePubKey:     share.GetPublicKey().Serialize(),
		Owner:           owner,
	}
	hash, err := newProof.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	proofSig, err := crypto.SignRSA(sk, hash[:])
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

// ValidateResults returns nil if results array is valid
func ValidateResults(
	operators []*Operator,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	amount phase0.Gwei,
	requestID [24]byte,
	results []*Result,
) (*bls.PublicKey, *phase0.DepositData, *bls.Sign, error) {
	t, err := ThresholdForCluster(operators)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(results) < int(t) || len(results) > len(operators) {
		return nil, nil, nil, fmt.Errorf("mistmatch results count")
	}

	// recover and validate validator pk
	pk, err := RecoverValidatorPKFromResults(results)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(validatorPK, pk) {
		return nil, nil, nil, fmt.Errorf("invalid recovered validator pubkey")
	}

	ids := make([]uint64, 0, len(results))
	sharePubKeys := make([]*bls.PublicKey, 0, len(results))
	sigsPartialDeposit := make([]*bls.Sign, 0, len(results))
	sigsPartialOwnerNonce := make([]*bls.Sign, 0, len(results))

	// validate individual result
	for _, result := range results {
		if err := ValidateResult(operators, ownerAddress, requestID, withdrawalCredentials, validatorPK, fork, nonce, amount, result); err != nil {
			return nil, nil, nil, err
		}
		pub, deposit, ownerNonce, err := GetPartialSigsFromResult(result)
		if err != nil {
			return nil, nil, nil, err
		}
		ids = append(ids, result.OperatorID)
		sharePubKeys = append(sharePubKeys, pub)
		sigsPartialDeposit = append(sigsPartialDeposit, deposit)
		sigsPartialOwnerNonce = append(sigsPartialOwnerNonce, ownerNonce)
	}

	// validate deposit data signature
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, sharePubKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to recover validator public key from results")
	}
	masterDepositSig, masterOwnerNonceSig, err := ReconstructMasterSignatures(ids, sigsPartialDeposit, sigsPartialOwnerNonce)
	if err != nil {
		return nil, nil, nil, err
	}
	network, err := core.NetworkFromForkVersion(fork)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := crypto.ValidateWithdrawalCredentials(withdrawalCredentials); err != nil {
		return nil, nil, nil, err
	}
	depositData := &phase0.DepositData{
		PublicKey:             phase0.BLSPubKey(validatorRecoveredPK.Serialize()),
		Amount:                phase0.Gwei(amount),
		WithdrawalCredentials: withdrawalCredentials,
		Signature:             phase0.BLSSignature(masterDepositSig.Serialize()),
	}
	err = crypto.VerifyDepositData(network, depositData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify master deposit signature: %v", err)
	}
	data := fmt.Sprintf("%s:%d", common.Address(ownerAddress).String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))
	if !masterOwnerNonceSig.VerifyByte(validatorRecoveredPK, hash) {
		return nil, nil, nil, fmt.Errorf("failed to verify master owner/nonce signature: %v", err)
	}
	return validatorRecoveredPK, depositData, masterOwnerNonceSig, nil
}

// ValidateResult returns nil if result is valid against init object
func ValidateResult(
	operators []*Operator,
	ownerAddress [20]byte,
	requestID [24]byte,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	nonce uint64,
	amount phase0.Gwei,
	result *Result,
) error {
	// verify operator
	operator := GetOperator(operators, result.OperatorID)
	if operator == nil {
		return fmt.Errorf("operator not found")
	}

	// verify request ID
	if !bytes.Equal(requestID[:], result.RequestID[:]) {
		return fmt.Errorf("invalid request ID")
	}

	if err := VerifyPartialSignatures(
		withdrawalCredentials,
		fork,
		ownerAddress,
		nonce,
		amount,
		result,
	); err != nil {
		return fmt.Errorf("failed to verify partial signatures: %v", err)
	}

	// verify ceremony proof
	if err := ValidateCeremonyProof(
		validatorPK,
		operator,
		result.SignedProof,
	); err != nil {
		return fmt.Errorf("failed to validate ceremony proof: %v", err)
	}

	return nil
}

// RecoverValidatorPKFromResults returns validator PK recovered from results
func RecoverValidatorPKFromResults(results []*Result) ([]byte, error) {
	ids := make([]uint64, len(results))
	pks := make([]*bls.PublicKey, len(results))

	for i, result := range results {
		pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
		if err != nil {
			return nil, err
		}
		pks[i] = pk
		ids[i] = result.OperatorID
	}

	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, pks)
	if err != nil {
		return nil, fmt.Errorf("failed to recover validator public key from results")
	}

	return validatorRecoveredPK.Serialize(), nil
}

func VerifyPartialSignatures(
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	amount phase0.Gwei,
	result *Result,
) error {
	pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
	if err != nil {
		return err
	}

	depositSig, err := BLSSignatureEncode(result.DepositPartialSignature)
	if err != nil {
		return err
	}

	nonceSig, err := BLSSignatureEncode(result.OwnerNoncePartialSignature)
	if err != nil {
		return err
	}

	if err := VerifyPartialDepositDataSignatures(
		withdrawalCredentials,
		fork,
		result.SignedProof.Proof.ValidatorPubKey,
		[]*bls.Sign{depositSig},
		[]*bls.PublicKey{pk},
		amount,
	); err != nil {
		return err
	}

	if err := VerifyPartialNonceSignatures(ownerAddress, nonce, []*bls.Sign{nonceSig}, []*bls.PublicKey{pk}); err != nil {
		return err
	}

	return nil
}

// PartialNonceRoot returns root for singing owner nonce
func PartialNonceRoot(address common.Address, nonce uint64) []byte {
	data := fmt.Sprintf("%s:%d", address.String(), nonce)
	return eth_crypto.Keccak256([]byte(data))
}

func VerifyPartialNonceSignatures(
	ownerAddress [20]byte,
	nonce uint64,
	sigs []*bls.Sign,
	pks []*bls.PublicKey,
) error {
	hash := PartialNonceRoot(ownerAddress, nonce)

	// Verify partial signatures and recovered threshold signature
	err := crypto.VerifyPartialSigs(sigs, pks, hash)
	if err != nil {
		return fmt.Errorf("failed to verify nonce partial signatures")
	}
	return nil
}

func VerifyPartialDepositDataSignatures(
	withdrawalCredentials []byte,
	fork [4]byte,
	validatorPubKey []byte,
	sigs []*bls.Sign,
	pks []*bls.PublicKey,
	amount phase0.Gwei,
) error {
	network, err := core.NetworkFromForkVersion(fork)
	if err != nil {
		return err
	}

	if err := crypto.ValidateWithdrawalCredentials(withdrawalCredentials); err != nil {
		return err
	}
	shareRoot, err := crypto.ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPubKey),
		Amount:                amount,
		WithdrawalCredentials: withdrawalCredentials,
	})
	if err != nil {
		return fmt.Errorf("failed to compute deposit data root: %w", err)
	}

	// Verify partial signatures and recovered threshold signature
	err = crypto.VerifyPartialSigs(sigs, pks, shareRoot[:])
	if err != nil {
		return fmt.Errorf("failed to verify deposit partial signatures: %w", err)
	}
	return nil
}

// GetOperator returns operator by ID or nil if not found
func GetOperator(operators []*Operator, id uint64) *Operator {
	for _, operator := range operators {
		if operator.ID == id {
			return operator
		}
	}
	return nil
}

func OperatorIDByPubKey(operators []*Operator, pkBytes []byte) (uint64, error) {
	for _, op := range operators {
		if bytes.Equal(op.PubKey, pkBytes) {
			return op.ID, nil
		}
	}
	return 0, fmt.Errorf("wrong operator")
}

func BLSPKEncode(pkBytes []byte) (*bls.PublicKey, error) {
	ret := &bls.PublicKey{}
	if err := ret.Deserialize(pkBytes); err != nil {
		return nil, err
	}

	return ret, nil
}

func BLSSignatureEncode(pkBytes []byte) (*bls.Sign, error) {
	ret := &bls.Sign{}
	if err := ret.Deserialize(pkBytes); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetPartialSigsFromResult(result *Result) (sharePubKey *bls.PublicKey, depositShareSig, ownerNonceShareSig *bls.Sign, err error) {
	sharePubKey = &bls.PublicKey{}
	if err := sharePubKey.Deserialize(result.SignedProof.Proof.SharePubKey); err != nil {
		return nil, nil, nil, err
	}
	depositShareSig = &bls.Sign{}
	if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
		return nil, nil, nil, err
	}
	ownerNonceShareSig = &bls.Sign{}
	if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
		return nil, nil, nil, err
	}
	return sharePubKey, depositShareSig, ownerNonceShareSig, nil
}

func ReconstructMasterSignatures(ids []uint64, sigsPartialDeposit, sigsPartialSSVContractOwnerNonce []*bls.Sign) (reconstructedDepositMasterSig, reconstructedOwnerNonceMasterSig *bls.Sign, err error) {
	reconstructedDepositMasterSig, err = crypto.RecoverBLSSignature(ids, sigsPartialDeposit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	reconstructedOwnerNonceMasterSig, err = crypto.RecoverBLSSignature(ids, sigsPartialSSVContractOwnerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	return reconstructedDepositMasterSig, reconstructedOwnerNonceMasterSig, nil
}
