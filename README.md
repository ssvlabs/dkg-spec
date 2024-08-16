# SSV Distributed Key Generation Spec

## Introduction
This repository contains spec of distributed key generation (DKG) used in SSV. Based on verifiable secret sharing, DKG allows a set of *n* operators to generate a  **BLS** key share for each operator, such that a BLS private key can only be used when threshold *t* out of *n* operators agree. 

---

## Functionalities
Operations are initiated by an initiator, and executed by operators. An initiator can initiate:

### Init
When a init message is sent to the operators, all operators participate and run a DKG ceremony to create key shares. A DKG ceremony asks each operator to verifiably share locally generated secrets with other operators, and combine secret shares from all operators to derive its own BLS key share. After the ceremony, each operator generates a **Result** with a **SignedProof** (see below) for verification. Proofs are referred to when an initiator asks for re-sign or reshare. 

### Re-sign
In the case where the nonces of a DKG ceremony is not correct, to prevent replay attack, the initiator sends re-sign messages for operators to create new signatures with correct nonces without generating new key shares. 

### Reshare
When the set of operators changed (including change of size and change of operators), a reshare is initiated to generate new key shares among the new operators. This process requires participation from *t* old operators and all new operators. 

---

## Validation in Ceremony
In a DKG ceremony, each message sent between the initiator and the operators are validated by the operators such that:
- The message is signed by the sender, preventing spoofing attacks.
- Where replay attacks are possible, a valid nonce is included to ensure the message is fresh (otherwise **Re-sign**).
-

---

## Post-Ceremony Validation: Result and Proof struct
After execution of init, re-sign and reshare, a **result** is returned by the operators for validation and verification.
```go
type Result struct {
	// Operator ID
	OperatorID uint64
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte `ssz-size:"24"`
	// Partial Operator Signature of Deposit data
	DepositPartialSignature []byte `ssz-size:"96"`
	// SSV owner + nonce signature
	OwnerNoncePartialSignature []byte `ssz-size:"96"`
	// Signed proof for the ceremony
	SignedProof SignedProof
}
```

In a **result**, the **SignedProof** is a **Proof** with a signature. A **Proof** contains:
```go
type Proof struct {
	// the resulting public key corresponding to the shared private key
	ValidatorPubKey []byte `ssz-size:"48"`
	// standard SSV encrypted share
	EncryptedShare []byte `ssz-max:"512"`
	// the share's BLS pubkey
	SharePubKey []byte `ssz-size:"48"`
	// owner address
	Owner [20]byte `ssz-size:"20"`
}
```
*ValidatorPubKey*, *EncryptedShare*, and *Owner* are to identify information of the validator and the operator in SSV network, the *SharePubKey* is computed by the operator after the DKG ceremony using the obtained secret share as the private key.

**Proof**s are published by the initiator after the DKG ceremony. All **Proof** from a ceremony together validates the completion of this ceremony. It makes sure:
- Partial signatures of operators are publically verifiable using the *SharePubKey* in the proof. If an operator created invalid partial signatures, the network is able to identify and potentially take further action.
- An operator knows its peers have completed the protocol locally and has a secret share ready to use. It prevents the case where some operators failed to derive their secret shares while others are unaware.
- The initiator refers to a completed valid DKG ceremony when initiating **Re-sign** and **Reshare**. Operators are able to identify and verify the corresponding ceremony when receiving requests from the initiator.


---

## Testing
The tests are located in the `testing/` folder. To run tests, use:
```shell
go generate ./...
```
then:
```shell
go test testing
```
