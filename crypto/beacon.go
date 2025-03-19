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
	MIN_ACTIVATION_BALANCE   phase0.Gwei = 32000000000
	MAX_EFFECTIVE_BALANCE    phase0.Gwei = 2048000000000
	ETH1WithdrawalPrefixByte             = byte(1)
)

// GetNetworkByFork translates the network fork bytes into name
//
//	TODO: once eth2_key_manager implements this we can get rid of it and support all networks ekm supports automatically
func GetNetworkByFork(fork [4]byte) (core.Network, error) {
	switch fork {
	case [4]byte{0x90, 0x00, 0x00, 0x69}:
		return core.SepoliaNetwork, nil
	case [4]byte{0x10, 0x00, 0x09, 0x10}:
		return core.HoodiNetwork, nil
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return core.PraterNetwork, nil
	case [4]byte{0x01, 0x01, 0x70, 0x00}:
		return core.HoleskyNetwork, nil
	case [4]byte{0, 0, 0, 0}:
		return core.MainNetwork, nil
	default:
		return core.MainNetwork, fmt.Errorf("unknown network")
	}
}

func ETH1WithdrawalCredentials(withdrawalAddr []byte) []byte {
	withdrawalCredentials := make([]byte, 32)
	copy(withdrawalCredentials[:1], []byte{ETH1WithdrawalPrefixByte})
	// withdrawalCredentials[1:12] == b'\x00' * 11 // this is not needed since cells are zeroed anyway
	copy(withdrawalCredentials[12:], withdrawalAddr)
	return withdrawalCredentials
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
	network, err := GetNetworkByFork(fork)
	if err != nil {
		return phase0.Root{}, err
	}
	return ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPK),
		Amount:                amount,
		WithdrawalCredentials: ETH1WithdrawalCredentials(withdrawalCredentials)})
}
