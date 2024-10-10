package spec

import (
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

func GetBulkMessageHash(bulkMsg []SSZMarshaller) ([32]byte, error) {
	hash := [32]byte{}
	msgBytes := []byte{}
	for _, msg := range bulkMsg {
		msrshalledMsg, err := msg.MarshalSSZ()
		if err != nil {
			return hash, err
		}
		msgBytes = append(msgBytes, msrshalledMsg...)
	}
	copy(hash[:], eth_crypto.Keccak256(msgBytes))
	return hash, nil
}

func GetReqIDFromMsg(message SSZMarshaller) ([24]byte, error) {
	// make a unique ID for each reshare using the instance hash
	reqID := [24]byte{}
	msgBytes, err := message.MarshalSSZ()
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

// NewID generates a random ID from 2 random concat UUIDs
func NewID() [24]byte {
	var id [24]byte
	b := uuid.New()
	copy(id[:12], b[:])
	b = uuid.New()
	copy(id[12:], b[:])
	return id
}
