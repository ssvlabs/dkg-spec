package spec

import eth_crypto "github.com/ethereum/go-ethereum/crypto"

func GetBulkMessageHash(bulkMsg []SSZMarshaller) ([32]byte, error) {
	hash := [32]byte{}
	msgBytes := []byte{}
	for _, resign := range bulkMsg {
		resignBytes, err := resign.MarshalSSZ()
		if err != nil {
			return hash, err
		}
		msgBytes = append(msgBytes, resignBytes...)
	}
	copy(hash[:], eth_crypto.Keccak256(msgBytes))
	return hash, nil
}

func GetReqIDFromMsg(instance SSZMarshaller) ([24]byte, error) {
	// make a unique ID for each reshare using the instance hash
	reqID := [24]byte{}
	msgBytes, err := instance.MarshalSSZ()
	if err != nil {
		return reqID, err
	}
	copy(reqID[:], eth_crypto.Keccak256(msgBytes))
	return reqID, nil
}

func FindOperatorPosition(operators []*Operator, id uint64) int {
	position := -1
	for i, operator := range operators {
		if operator.ID == id {
			position = i
			break
		}
	}
	return position
}
