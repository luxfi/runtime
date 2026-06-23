// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package runtime provides chain wiring and runtime dependencies for VMs.
// This package is part of the consensus module and provides the Runtime struct
// that VMs use for chain configuration, logging, validators, etc.
//
// Use stdlib context.Context for cancellation/deadlines.
// Use *Runtime for chain wiring (IDs, logging, validators, etc.)
package runtime

import (
	"context"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/metric"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/luxfi/warp"
)

// ValidatorState is an alias to validators.State for convenience
type ValidatorState = validators.State

// Runtime provides chain wiring and runtime dependencies for VMs.
// This is separate from stdlib context.Context which handles cancellation/deadlines.
//
// Use context.Context for:
//   - Cancellation signals
//   - Request deadlines
//   - Request-scoped values (sparingly)
//
// Use *Runtime for:
//   - Chain IDs, network IDs
//   - Node identity (NodeID, PublicKey)
//   - Logging, metrics
//   - Database handles
//   - Validator state
//   - Upgrade configurations
type Runtime struct {
	// NetworkID is the numeric network identifier (1=mainnet, 2=testnet)
	NetworkID uint32 `json:"networkID"`

	// ChainID identifies the specific chain within the network
	ChainID ids.ID `json:"chainID"`

	// NodeID identifies this node
	NodeID ids.NodeID `json:"nodeID"`

	// PublicKey is the node's BLS public key bytes
	PublicKey []byte `json:"publicKey"`

	// XChainID is the X-Chain identifier
	XChainID ids.ID `json:"xChainID"`

	// CChainID is the C-Chain identifier
	CChainID ids.ID `json:"cChainID"`

	// GovernanceController is the 20-byte EVM address of the DEX governance
	// authority — the ONLY caller that may toggle the 0x9999 settlement kill
	// switches (setHaltGlobal/Market/Asset) and seed the settlement pots. It is a
	// per-NETWORK identity (each network deploys its own Governor/Timelock/multisig
	// CONTRACT), resolved at chain wiring from the host's deployment topology and
	// surfaced to the precompile via contract.AtomicState.GovernanceController() —
	// the SAME runtime seam CChainID/DChainID flow through, with ZERO per-net config
	// file. It MUST be a governance CONTRACT, NEVER an EOA derivable from any dev
	// mnemonic. The zero value is the safe default: an unset governance authority
	// makes the halt switches uncallable (fail-closed — no single key can DoS the
	// DEX), never fail-open. Typed ids.ShortID ([20]byte) so this low consensus leaf
	// stays free of any geth import; it is the same 20 bytes as a geth common.Address.
	GovernanceController ids.ShortID `json:"governanceController"`

	// UTXOAssetID is the primary network's UTXO fee asset — burned to
	// pay fees on P-chain (CreateChainTx, AddChainValidatorTx, …) and
	// X-chain transfers. Sourced from the chain's genesis (the X-chain's
	// native asset by upstream convention; on a sovereign L1 it's
	// whatever native the chain bootstraps with — LUX on Lux primary,
	// the L1's native on each downstream L1). Same number on P and X
	// by construction; named for the function, not the chain.
	UTXOAssetID ids.ID `json:"utxoAssetID"`

	// ChainDataDir is the directory for chain-specific data
	ChainDataDir string `json:"chainDataDir"`

	// StartTime is when the node started
	StartTime time.Time `json:"startTime"`

	// PChainHeight is the optional proposer P-Chain height for block-specific operations.
	PChainHeight uint64 `json:"pChainHeight"`

	// ValidatorState provides validator information (uses consensus/validators.State)
	ValidatorState validators.State

	// Keystore provides key management
	Keystore Keystore

	// Metrics provides metrics tracking
	Metrics Metrics

	// Log provides logging
	Log Logger

	// SharedMemory provides cross-chain atomic operations
	SharedMemory SharedMemory

	// BCLookup provides blockchain alias lookup
	BCLookup BCLookup

	// WarpSigner provides BLS signing for Warp messages
	WarpSigner WarpSigner

	// Sender is the canonical warp sender
	Sender warp.Sender

	// Lock for thread-safe access to runtime fields
	Lock sync.RWMutex
}

// BCLookup provides blockchain alias lookup
type BCLookup interface {
	Lookup(alias string) (ids.ID, error)
	PrimaryAlias(id ids.ID) (string, error)
	Aliases(id ids.ID) ([]string, error)
}

// Keystore provides key management
type Keystore interface {
	GetDatabase(username, password string) (interface{}, error)
	NewAccount(username, password string) error
}

// Logger provides logging functionality
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	IsZero() bool
}

// Metrics provides metrics tracking.
// Matches api/metrics.MultiGatherer interface.
type Metrics interface {
	metric.Gatherer
	Register(name string, gatherer metric.Gatherer) error
}

// SharedMemory is the canonical interface for cross-chain atomic operations.
// Uses atomic.Requests and atomic.Element as the ONE canonical types.
type SharedMemory = atomic.SharedMemory

// WarpSigner provides BLS signing for Warp messages.
// Matches warp.Signer interface exactly.
type WarpSigner = warp.Signer

// VMContext is an interface that VM contexts must implement
// This allows different context types (node, plugin, etc.) to be used interchangeably
type VMContext interface {
	GetNetworkID() uint32
	GetChainID() ids.ID
	GetNodeID() ids.NodeID
	GetPublicKey() []byte
	GetXChainID() ids.ID
	GetCChainID() ids.ID
	GetAssetID() ids.ID
	GetChainDataDir() string
	GetLog() Logger
	GetSharedMemory() SharedMemory
	GetMetrics() Metrics
	GetValidatorState() ValidatorState
	GetBCLookup() BCLookup
	GetWarpSigner() WarpSigner
	GetSender() warp.Sender
}

// IDs holds the IDs for runtime context
type IDs struct {
	NetworkID    uint32
	ChainID      ids.ID
	NodeID       ids.NodeID
	PublicKey    []byte
	UTXOAssetID  ids.ID
	ChainDataDir string `json:"chainDataDir"`
}

// GetTimestamp returns the current timestamp
func GetTimestamp() int64 {
	return time.Now().Unix()
}

// AsBCLookup returns the BCLookup interface for blockchain alias lookup.
// This method is used by VMs (particularly coreth) to resolve chain aliases.
func (r *Runtime) AsBCLookup() BCLookup {
	if r == nil {
		return nil
	}
	return r.BCLookup
}

// VMContext interface implementation
// These methods allow *Runtime to satisfy the VMContext interface
// used by VM plugins (coreth, etc.) for chain initialization.

func (r *Runtime) GetNetworkID() uint32 {
	if r == nil {
		return 0
	}
	return r.NetworkID
}

func (r *Runtime) GetChainID() ids.ID {
	if r == nil {
		return ids.Empty
	}
	return r.ChainID
}

func (r *Runtime) GetNodeID() ids.NodeID {
	if r == nil {
		return ids.EmptyNodeID
	}
	return r.NodeID
}

func (r *Runtime) GetPublicKey() []byte {
	if r == nil {
		return nil
	}
	return r.PublicKey
}

func (r *Runtime) GetXChainID() ids.ID {
	if r == nil {
		return ids.Empty
	}
	return r.XChainID
}

func (r *Runtime) GetCChainID() ids.ID {
	if r == nil {
		return ids.Empty
	}
	return r.CChainID
}

// GetGovernanceController returns the DEX governance authority address (the sole
// caller permitted to halt 0x9999 settlement / seed its pots), or the zero ShortID
// when unset — which the precompile treats as fail-closed (no halt authority).
func (r *Runtime) GetGovernanceController() ids.ShortID {
	if r == nil {
		return ids.ShortEmpty
	}
	return r.GovernanceController
}

func (r *Runtime) GetAssetID() ids.ID {
	if r == nil {
		return ids.Empty
	}
	return r.UTXOAssetID
}

func (r *Runtime) GetChainDataDir() string {
	if r == nil {
		return ""
	}
	return r.ChainDataDir
}

func (r *Runtime) GetLog() Logger {
	if r == nil {
		return nil
	}
	return r.Log
}

func (r *Runtime) GetSharedMemory() SharedMemory {
	if r == nil {
		return nil
	}
	return r.SharedMemory
}

func (r *Runtime) GetMetrics() Metrics {
	if r == nil {
		return nil
	}
	return r.Metrics
}

func (r *Runtime) GetValidatorState() ValidatorState {
	if r == nil {
		return nil
	}
	return r.ValidatorState
}

func (r *Runtime) GetBCLookup() BCLookup {
	if r == nil {
		return nil
	}
	return r.BCLookup
}

func (r *Runtime) GetWarpSigner() WarpSigner {
	if r == nil {
		return nil
	}
	return r.WarpSigner
}

func (r *Runtime) GetSender() warp.Sender {
	if r == nil {
		return nil
	}
	return r.Sender
}

// Ensure *Runtime implements VMContext at compile time
var _ VMContext = (*Runtime)(nil)

// GetValidatorOutput is re-exported from validator package for convenience
type GetValidatorOutput = validators.GetValidatorOutput

// Context is an alias for *Runtime for backwards compatibility with old consensus context patterns
type Context = Runtime

// contextKey is used for storing runtime in stdlib context
type contextKey struct{}

// WithContext returns a new context.Context with the runtime embedded.
// This allows extracting chain info from a stdlib context using FromContext.
func WithContext(ctx context.Context, chainCtx interface{}) context.Context {
	if r, ok := chainCtx.(*Runtime); ok {
		return context.WithValue(ctx, contextKey{}, r)
	}
	return ctx
}

// FromContext extracts the Runtime from a stdlib context.Context.
// Returns nil if no runtime is embedded.
func FromContext(ctx context.Context) *Runtime {
	if r, ok := ctx.Value(contextKey{}).(*Runtime); ok {
		return r
	}
	return nil
}

// GetChainID extracts chain ID from context (backwards compatibility)
func GetChainID(ctx context.Context) ids.ID {
	if r := FromContext(ctx); r != nil {
		return r.ChainID
	}
	return ids.Empty
}

// GetNetworkID extracts network ID from context (backwards compatibility)
func GetNetworkID(ctx context.Context) uint32 {
	if r := FromContext(ctx); r != nil {
		return r.NetworkID
	}
	return 0
}

// GetValidatorState extracts validator state from context (backwards compatibility)
func GetValidatorState(ctx context.Context) ValidatorState {
	if r := FromContext(ctx); r != nil {
		return r.ValidatorState
	}
	return nil
}

// validatorStateKey is used for storing validator state in stdlib context
type validatorStateKey struct{}

// WithValidatorState adds a validator state to the context (backwards compatibility)
func WithValidatorState(ctx context.Context, state ValidatorState) context.Context {
	return context.WithValue(ctx, validatorStateKey{}, state)
}

// GetValidatorStateFromKey extracts validator state from context using key (backwards compatibility)
func GetValidatorStateFromKey(ctx context.Context) ValidatorState {
	if state, ok := ctx.Value(validatorStateKey{}).(ValidatorState); ok {
		return state
	}
	// Fall back to trying to get from Runtime
	return GetValidatorState(ctx)
}
