# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go library (`github.com/ssvlabs/dkg-spec`) defining the specification for SSV's Distributed Key Generation (DKG) protocol. Operators use BLS threshold cryptography to generate shared validator keys for Ethereum — no single operator holds the full private key.

## Build & Test Commands

```bash
# Generate SSZ encoding (types_encoding.go) and EIP-1271 bindings
# Requires: abigen (geth tools) for eip1271 contract generation
go generate ./...

# Build
go build -v ./...

# Run all tests (tests live in testing/ package, not ./...)
go test ./testing/ ./crypto/

# Run a single test
go test ./testing/ -run TestValidateResults
go test ./crypto/ -run TestVerifyDepositData
```

**Important**: `go test` at root runs nothing useful. Tests are in `testing/` and `crypto/` packages.

## Architecture

### Three DKG Operations

All operations follow the same pattern: **initiator** sends a request, **operators** execute the ceremony, each operator produces a `Result` containing a `SignedProof`.

1. **Init** (`init.go`, `operator.go:Init`) — Fresh DKG ceremony creating new BLS key shares
2. **Reshare** (`reshare.go`, `operator.go:Reshare`) — Redistribute shares to a new operator set. Requires owner ECDSA/EIP-1271 signature and proofs from the previous ceremony
3. **Resign** (`resign.go`, `operator.go:Resign`) — Re-sign with corrected nonces without generating new keys. Also requires owner signature

### Key Data Flow

`Init/Reshare/Resign` message → operator validates → DKG ceremony (stubbed in spec) → `BuildResult()` → `Result` containing:
- `DepositPartialSignature` — BLS partial sig over ETH2 deposit data
- `OwnerNoncePartialSignature` — BLS partial sig over `owner:nonce` hash
- `SignedProof` — RSA-signed proof linking validator pubkey, encrypted share, share pubkey, and owner

`ValidateResults()` in `result.go` is the main verification entry point: recovers the master public key from shares, reconstructs master signatures, and verifies deposit data against the Ethereum network fork.

### Cryptography Layers (`crypto/`)

- **BLS** (`bls.go`) — Threshold key recovery and partial signature verification using `herumi/bls-eth-go-binary`. Must call `InitBLS()` before use.
- **RSA** (`rsa.go`) — Operator key pairs for encrypting shares and signing proofs (PSS signatures, PKCS1v15 encryption). Operator public keys are base64-encoded PEM.
- **Beacon** (`beacon.go`) — ETH2 deposit data computation and verification. Network determined by fork version bytes. Withdrawal credentials must be 32 bytes with a valid prefix: 0x01 (ETH1) or 0x02 (compounding). Use `WithdrawalCredentials(prefix, addr)` to construct them from a prefix byte and a 20-byte address.
- **Owner Signature** (`signature.go`) — Verifies owner authorization via either EOA (ECDSA with EIP-155 chain ID support) or smart contract wallet (EIP-1271).

### Encoding

All types use SSZ serialization. `types_encoding.go` is auto-generated from `types.go` via `fastssz/sszgen`. The `SSZMarshaller` interface is used for bulk message hashing (reshare/resign flows).

### Valid Cluster Sizes

Only 4 fixed operator counts are supported: **4** (t=3), **7** (t=5), **10** (t=7), **13** (t=9). Threshold follows `t = 2f+1` where `n = 3f+1`.

### Testing Structure

- `testing/` — Integration tests for init, result, reshare, resign validation
- `testing/fixtures/` — Deterministic test data: hardcoded RSA operator keys, BLS shares, pre-computed signatures and proofs for 4/7/10/13 operator configurations
- `testing/stubs/` — Mock `ETHClient` for EIP-1271/EOA signature verification
- `crypto/` — Unit tests for beacon deposit computation and BLS signature verification

### Generated Files (do not edit manually)

- `types_encoding.go` — SSZ marshaling from `go generate` on `types.go`
- `eip1271/eip1271.go` — Contract bindings from `abigen` on `eip1271/abi.abi`
