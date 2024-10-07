# SSV Distributed Key Generation Spec

## Introduction
This repository contains spec of distributed key generation (DKG) used in SSV. Based on verifiable secret sharing, DKG allows a set of *n* operators to generate a  **BLS** key share for each operator, such that a BLS private key can only be used when threshold $t$ out of $n$ operators agree. $t$ is defined by the number of faults admissible: $t = n - f$, where $n = 3 * f + 1$.

---

## Functionalities
Operations are initiated by an initiator, and executed by operators. An initiator can initiate:

### Init
When a init message is sent to the operators, all operators participate and run a DKG ceremony to create key shares. A DKG ceremony asks each operator to verifiably share locally generated secrets with other operators, and combine secret shares from all operators to derive its own BLS key share. An init message specifies an owner ethAddress. The owner is the entity that owns the Ethereum validator which the generated secret shares control. After the ceremony, each operator generates a **Result** with a **SignedProof** (see below) for verification. Proofs are referred to when an initiator asks for re-sign or reshare. 

### Re-sign
In the case where the nonces of a DKG ceremony is not correct, to prevent replay attack, the initiator sends re-sign messages for operators to create new signatures with correct nonces without generating a new validator key. For operators to perform re-sign, owner's secret key must be used to sign a re-sign message, convincing the operators that the request is regarding a completed ceremony and it is indeed the owner of this ceremony that requested to re-sign.

### Reshare
When the set of operators changed (including change of size and change of operators), a reshare is initiated to generate new key shares among the new operators. This process requires participation from *t* old operators and all new operators. For operators to perform reshare, owner's secret key must be used to sign a reshare message, convincing the operators that the request is regarding a completed ceremony and it is indeed the owner of this ceremony that requested to reshare.


---

## Security Assumptions
All messages are authenticated using the initiator's and operators' public keys. Initiators and operators are assumed to keep their secret keys secure. An initiator has no motivation to deviate from the protocol or trick operators to create unexpected results, because wrong DKG outputs only damage the initator itself, e.g. operators will not be able to perform duties for the initiator if DKG key shares are incorrect. 

---

## Validations
In a DKG ceremony, each message sent between the initiator and the operators are validated by the operators such that:
- The message is signed by the sender, preventing spoofing attacks.
- Where replay attacks are possible, a valid nonce is included to ensure the message is fresh (otherwise **Re-sign**).
- The message is in the same scope, i.e., the message is regarding the same ceremony, the same set of operators and it is in the correct stage as the receiver expects.

---

## Result and Proof struct
After execution of init, re-sign and reshare, a **result** is returned by the operators as an important validation for the completion of the ceremony.
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
As a 4-operator example, after the ceremony, each operator $i$ obtains a secret share $s_i$. The aggregated secret key $S$ can be recovered from any 3 out of the 4 secret shares $s_1, s_2, s_3, s_4$. In this example, *ValidatorPubKey* is the public key of the aggregated secret $S$. *EncryptedShare* is the encrypted secret share of the operator, e.g. encrypted $s_1$ for operator 1. *SharePubKey* is the corresponding public key of the operator's secret share $s_i$. 

**Proof**s are published by the initiator after the DKG ceremony. All **Proof** from a ceremony together validates the completion of this ceremony. they can make sure:
- Partial signatures of operators are publically verifiable using the *SharePubKey* in the **proof** with BLS signature verification (given the message, *SharePubKey*, and the signature, returns whether the signature is valid or not). If an operator created invalid partial signatures, the network is able to identify and potentially take further action.
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
