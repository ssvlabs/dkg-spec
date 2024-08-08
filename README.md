# SSV Distributed Key Generation Spec

## Introduction
This repository contains spec of distributed key generation (DKG) used in SSV. Based on verifiable secret sharing, DKG allows a set of *n* operators to generate a  **BLS** key share for each operator, such that a BLS private key can only be used when threshold *t* out of *n* operators agree. 

---

## Functionalities
Operations are initiated by an initiator, and executed by operators. An initiator can initiate:

### Init
When a init message is sent to the operators, all operators participate and run a DKG ceremony to create key shares. Each operator generates a result with a **proof** to show the correctness of execution. Proofs are referred to when an initiator asks for re-sign or reshare. The encrypted share can be found in a proof as it could be published to a smart contract.

### Re-sign
In the case where the nonces of a DKG ceremony is not correct, the initiator sends re-sign messages for operators to create new signatures with correct nonces without generating new key shares.

### Reshare
When the set of operators changed, a reshare is initiated to generate new key shares among the new operators. This process requires participation from t old operators and all new operators. 

---

## Result struct
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
