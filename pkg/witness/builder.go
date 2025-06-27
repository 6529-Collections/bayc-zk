// pkg/witness/builder.go
package witness

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/mpt"
	"github.com/yourorg/bayczk/pkg/slot"
)

// Builder contains all the required fields for building circuit witnesses
type Builder struct {
	AccountProof [][]uints.U8
	AccountPath  []uints.U8
	StorageProof [][]uints.U8
	StoragePath  []uints.U8
	StateRoot    frontend.Variable
	Owner        string // hex address without 0x prefix
	TokenID      *big.Int
	OwnerBytes   []uints.U8 // Real 32-byte storage slot value from RPC
}

// proofResponse represents the JSON structure from the RPC proof response
type proofResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Address      string   `json:"address"`
		AccountProof []string `json:"accountProof"`
		Balance      string   `json:"balance"`
		CodeHash     string   `json:"codeHash"`
		Nonce        string   `json:"nonce"`
		StorageHash  string   `json:"storageHash"`
		StorageProof []struct {
			Key   string   `json:"key"`
			Value string   `json:"value"`
			Proof []string `json:"proof"`
		} `json:"storageProof"`
	} `json:"result"`
}

// headerResponse represents the JSON structure from the header response
type headerResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		StateRoot string `json:"stateRoot"`
	} `json:"result"`
}

func hexToNibbles(h [32]byte) []uints.U8 {
	out := make([]uints.U8, 64)
	for i, b := range h {
		out[2*i] = mpt.ConstU8(b >> 4)     // high nibble
		out[2*i+1] = mpt.ConstU8(b & 0x0f) // low  nibble
	}
	return out
}

func toU8Slice(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b {
		out[i] = mpt.ConstU8(v)
	}
	return out
}

// FromFixtures loads test fixture data from JSON files and creates a Builder
// Hard-coded to use Doodles token ID 8822 and fixture directory for now
func FromFixtures(dir string) (*Builder, error) {
	// Hard-code paths for now as specified
	proofPath := filepath.Join(dir, "proof_doodles_8822.json")
	headerPath := filepath.Join(dir, "header_latest.json")
	
	// Load proof data
	proofData, err := os.ReadFile(proofPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	
	var proof proofResponse
	if err := json.Unmarshal(proofData, &proof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof: %w", err)
	}
	
	// Load header data  
	headerData, err := os.ReadFile(headerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read header file: %w", err)
	}
	
	var header headerResponse
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	
	// Convert account proof
	var accountProof [][]uints.U8
	for _, hexProof := range proof.Result.AccountProof {
		raw, err := hex.DecodeString(hexProof[2:]) // Remove 0x prefix
		if err != nil {
			return nil, fmt.Errorf("failed to decode account proof: %w", err)
		}
		accountProof = append(accountProof, toU8Slice(raw))
	}
	
	// Convert storage proof (use first storage proof entry)
	var storageProof [][]uints.U8
	if len(proof.Result.StorageProof) > 0 {
		for _, hexProof := range proof.Result.StorageProof[0].Proof {
			raw, err := hex.DecodeString(hexProof[2:]) // Remove 0x prefix
			if err != nil {
				return nil, fmt.Errorf("failed to decode storage proof: %w", err)
			}
			storageProof = append(storageProof, toU8Slice(raw))
		}
	}
	
	// Extract contract address and create account path
	contractAddr := common.HexToAddress(proof.Result.Address)
	accountPath := hexToNibbles(crypto.Keccak256Hash(contractAddr.Bytes()))
	
	// Hard-code token ID 8822 for now
	tokenID := big.NewInt(8822)
	
	// Create storage path for this token ID
	slotKey := slot.Calc(tokenID, 0)
	storagePath := hexToNibbles(slotKey)
	
	// Extract state root
	stateRootBytes := common.HexToHash(header.Result.StateRoot)
	stateRoot := new(big.Int).SetBytes(stateRootBytes.Bytes())
	
	// Extract the real storage slot value from RPC proof
	var realStorageValue []byte
	var realOwnerAddress string
	
	if len(proof.Result.StorageProof) > 0 {
		// Get the actual storage slot value from the RPC proof
		storageValueHex := proof.Result.StorageProof[0].Value
		if storageValueHex == "0x0" || storageValueHex == "0x" {
			// Storage slot is empty - create 32 zero bytes
			realStorageValue = make([]byte, 32)
			// For empty slots, we'll use a zero address as expected owner
			realOwnerAddress = "0000000000000000000000000000000000000000"
		} else {
			// Parse the actual storage value
			if len(storageValueHex) > 2 {
				decoded, err := hex.DecodeString(storageValueHex[2:]) // Remove 0x prefix
				if err != nil {
					return nil, fmt.Errorf("failed to decode storage value: %w", err)
				}
				
				// Handle different storage formats:
				// - Doodles: 20-byte address directly
				// - Other contracts: 32-byte slot with address in last 20 bytes
				if len(decoded) == 20 {
					// Direct address storage (like Doodles)
					realStorageValue = make([]byte, 32)
					copy(realStorageValue[12:32], decoded) // Pad to 32 bytes, address in last 20 bytes
					realOwnerAddress = hex.EncodeToString(decoded)
				} else {
					// 32-byte slot storage
					realStorageValue = make([]byte, 32)
					copy(realStorageValue[32-len(decoded):], decoded)
					
					// Extract owner address from storage slot (last 20 bytes)
					if len(realStorageValue) >= 20 {
						ownerBytes := realStorageValue[12:32] // Bytes 12-31 (20 bytes)
						realOwnerAddress = hex.EncodeToString(ownerBytes)
					} else {
						realOwnerAddress = "0000000000000000000000000000000000000000"
					}
				}
			} else {
				realStorageValue = make([]byte, 32)
				realOwnerAddress = "0000000000000000000000000000000000000000"
			}
		}
	} else {
		// Fallback if no storage proof
		realStorageValue = make([]byte, 32)
		realOwnerAddress = "0000000000000000000000000000000000000000"
	}
	
	return &Builder{
		AccountProof: accountProof,
		AccountPath:  accountPath,
		StorageProof: storageProof,
		StoragePath:  storagePath,
		StateRoot:    stateRoot,
		Owner:        realOwnerAddress, // Real owner address from storage slot
		TokenID:      tokenID,
		OwnerBytes:   toU8Slice(realStorageValue), // Real 32-byte storage slot value
	}, nil
}

func Build(
	ctx context.Context,
	rpc string,
	block uint64,
	contract common.Address,
	tokenID *big.Int,
	expOwner common.Address,
) (*Bundle, error) {

	cli, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	proof, err := FetchProof(ctx, cli, contract, common.Hash{}, block)
	if err != nil {
		return nil, err
	}
	headerRoot, err := FetchStateRoot(ctx, cli, block)
	if err != nil {
		return nil, err
	}

	var accNodes [][]uints.U8
	for _, h := range proof.AccountProof {
		raw, _ := hex.DecodeString(h[2:])
		accNodes = append(accNodes, toU8Slice(raw))
	}

	var storNodes [][]uints.U8
	for _, h := range proof.StorageProof[0].Proof {
		raw, _ := hex.DecodeString(h[2:])
		storNodes = append(storNodes, toU8Slice(raw))
	}

	// Extract the real storage slot value from RPC proof response
	var realStorageValue []byte
	var realOwnerAddress common.Address
	
	if len(proof.StorageProof) > 0 {
		storageValueHex := proof.StorageProof[0].Value
		if storageValueHex == "0x0" || storageValueHex == "0x" {
			// Storage slot is empty
			realStorageValue = make([]byte, 32)
			realOwnerAddress = common.Address{} // Zero address
		} else {
			// Parse the actual storage value
			if len(storageValueHex) > 2 {
				decoded, err := hex.DecodeString(storageValueHex[2:])
				if err != nil {
					return nil, fmt.Errorf("failed to decode storage value: %w", err)
				}
				// Pad to 32 bytes if necessary
				realStorageValue = make([]byte, 32)
				copy(realStorageValue[32-len(decoded):], decoded)
				
				// Extract owner address from storage slot (last 20 bytes)
				if len(realStorageValue) >= 20 {
					copy(realOwnerAddress[:], realStorageValue[12:32])
				}
			} else {
				realStorageValue = make([]byte, 32)
				realOwnerAddress = common.Address{}
			}
		}
	} else {
		realStorageValue = make([]byte, 32)
		realOwnerAddress = common.Address{}
	}
	
	ownerVal := toU8Slice(realStorageValue)              // Real 32-byte storage slot value
	expectedOwner := toU8Slice(expOwner.Bytes())         // Expected owner address (test parameter)

	accPath := hexToNibbles(crypto.Keccak256Hash(contract.Bytes()))
	slotKey := slot.Calc(tokenID, 0)
	storPath := hexToNibbles(slotKey)

	// Storage proof structure analysis complete - nodes: 532, 532, 532, 372, 115, 54 bytes

	assignment := &circuits.BaycOwnershipCircuit{
		StateRoot:     headerRoot.Big(),
		TokenID:       tokenID,
		ExpectedOwner: expectedOwner,   // 20-byte owner address
		AccountProof:  accNodes,
		StorageProof:  storNodes,
		AccountPath:   accPath,
		StoragePath:   storPath,
		OwnerBytes:    ownerVal,        // 32-byte storage slot value
	}
	full, _ := frontend.NewWitness(assignment, circuits.Curve().ScalarField())

	blue := &circuits.BaycOwnershipCircuit{
		ExpectedOwner: make([]uints.U8, len(expectedOwner)),
		AccountProof:  make([][]uints.U8, len(accNodes)),
		StorageProof:  make([][]uints.U8, len(storNodes)),
		AccountPath:   make([]uints.U8, len(accPath)),
		StoragePath:   make([]uints.U8, len(storPath)),
		OwnerBytes:    make([]uints.U8, len(ownerVal)),
	}
	for i, n := range accNodes {
		ln := len(n)
		if ln == 0 {
			ln = 1
		}
		blue.AccountProof[i] = make([]uints.U8, ln)
	}
	for i, n := range storNodes {
		ln := len(n)
		if ln == 0 {
			ln = 1
		}
		blue.StorageProof[i] = make([]uints.U8, ln)
	}

	pub := PublicInputs{
		StateRoot: headerRoot,
		TokenID:   tokenID.String(),
		Owner:     expOwner.Hex()[2:], // Expected owner (test parameter)
	}

	return &Bundle{Full: full, Public: pub, Blueprint: blue}, nil
}
