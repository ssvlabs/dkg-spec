package crypto

import (
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// RecoverValidatorPublicKey recovers a BLS master public key (validator pub key) from provided partial pub keys
func RecoverValidatorPublicKey(ids []uint64, sharePks []*bls.PublicKey) (*bls.PublicKey, error) {
	if len(ids) != len(sharePks) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *sharePks[i])
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return nil, err
	}
	return &validatorRecoveredPK, nil
}

func VerifyPartialSigs(sigs []*bls.Sign, pubs []*bls.PublicKey, data []byte) error {
	for i, sig := range sigs {
		if !sig.VerifyByte(pubs[i], data) {
			return fmt.Errorf("partial signature is invalid  #%d: sig %x root %x", i, sig.Serialize(), data)
		}
	}
	return nil
}

// RecoverBLSSignature recovers a BLS master signature from T-threshold partial signatures
func RecoverBLSSignature(ids []uint64, partialSigs []*bls.Sign) (*bls.Sign, error) {
	if len(ids) != len(partialSigs) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	reconstructed := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *partialSigs[i])
	}
	if err := reconstructed.Recover(sigVec, idVec); err != nil {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	return &reconstructed, nil
}
