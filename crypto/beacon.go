package crypto

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ssvlabs/eth2-key-manager/core"
	eth1deposit "github.com/ssvlabs/eth2-key-manager/eth1_deposit"
	types "github.com/wealdtech/go-eth2-types/v2"
)

const (
	// https://eips.ethereum.org/EIPS/eip-7251
	MIN_ACTIVATION_BALANCE      phase0.Gwei = 32000000000
	MAX_EFFECTIVE_BALANCE       phase0.Gwei = 2048000000000
	ETH1WithdrawalPrefix                    = byte(1)
	CompoundingWithdrawalPrefix             = byte(2)
)

// WithdrawalCredentials constructs 32-byte withdrawal credentials from a prefix byte and a 20-byte address.
func WithdrawalCredentials(prefix byte, withdrawalAddr []byte) []byte {
	creds := make([]byte, 32)
	creds[0] = prefix
	copy(creds[12:], withdrawalAddr)
	return creds
}

// ValidateWithdrawalCredentials checks that credentials are exactly 32 bytes with a valid prefix (0x01 or 0x02).
// Bytes [1:12] (zero padding) are not enforced — the Ethereum beacon chain accepts any padding,
// and WithdrawalCredentials() always zero-pads.
func ValidateWithdrawalCredentials(creds []byte) error {
	if len(creds) != 32 {
		return fmt.Errorf("withdrawal credentials must be 32 bytes, got %d", len(creds))
	}
	if creds[0] != ETH1WithdrawalPrefix && creds[0] != CompoundingWithdrawalPrefix {
		return fmt.Errorf("invalid withdrawal credential prefix: 0x%02x", creds[0])
	}
	return nil
}

func ComputeDepositMessageSigningRoot(network core.Network, message *phase0.DepositMessage) (phase0.Root, error) {
	if !eth1deposit.IsSupportedDepositNetwork(network) {
		return phase0.Root{}, fmt.Errorf("network %s is not supported", network)
	}

	// Compute DepositMessage root.
	depositMsgRoot, err := message.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to calculate domain: %s", err)
	}
	container := &phase0.SigningData{
		ObjectRoot: depositMsgRoot,
		Domain:     phase0.Domain(domain),
	}
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to determine the root hash of signing container: %s", err)
	}
	return signingRoot, nil
}

// VerifyDepositData reconstructs and checks BLS signatures for ETH2 deposit message
func VerifyDepositData(network core.Network, depositData *phase0.DepositData) error {
	signingRoot, err := ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             depositData.PublicKey,
		Amount:                depositData.Amount,
		WithdrawalCredentials: depositData.WithdrawalCredentials,
	})
	if err != nil {
		return fmt.Errorf("failed to compute signing root: %s", err)
	}

	// Verify the signature.
	pkCopy := make([]byte, len(depositData.PublicKey))
	copy(pkCopy, depositData.PublicKey[:])
	pubkey, err := types.BLSPublicKeyFromBytes(pkCopy)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %s", err)
	}

	sigCpy := make([]byte, len(depositData.Signature))
	copy(sigCpy, depositData.Signature[:])
	sig, err := types.BLSSignatureFromBytes(sigCpy)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}
	if !sig.Verify(signingRoot[:], pubkey) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func DepositDataRootForFork(
	fork [4]byte,
	validatorPK []byte,
	withdrawalCredentials []byte,
	amount phase0.Gwei,
) (phase0.Root, error) {
	network, err := core.NetworkFromForkVersion(fork)
	if err != nil {
		return phase0.Root{}, err
	}
	if err := ValidateWithdrawalCredentials(withdrawalCredentials); err != nil {
		return phase0.Root{}, err
	}
	return ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPK),
		Amount:                amount,
		WithdrawalCredentials: withdrawalCredentials,
	})
}
