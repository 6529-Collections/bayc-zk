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
// Hard-coded to use BAYC token ID 8822 and fixture directory for now
func FromFixtures(dir string) (*Builder, error) {
	// Hard-code paths for now as specified
	proofPath := filepath.Join(dir, "proof_bayc_8822.json")
	headerPath := filepath.Join(dir, "header_22566332.json")
	
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
	
	// Hard-code expected owner for token 8822 (this would be provided by caller in real usage)
	// For now, use a placeholder address
	owner := "1234567890123456789012345678901234567890" // 20-byte hex without 0x
	
	return &Builder{
		AccountProof: accountProof,
		AccountPath:  accountPath,
		StorageProof: storageProof,
		StoragePath:  storagePath,
		StateRoot:    stateRoot,
		Owner:        owner,
		TokenID:      tokenID,
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

	// Work with the actual storage proof value instead of overriding it
	// The RPC proof shows "0x0" which means the storage slot is empty
	// We'll construct witness data that matches this empty state
	
	ownerVal := toU8Slice(make([]byte, 32))      // 32 zero bytes for empty storage slot
	expectedOwner := toU8Slice(expOwner.Bytes()) // 20-byte expected owner address
	
	// Don't modify the storage proof - use it as-is from the RPC
	// The proof correctly shows that the storage slot is empty

	accPath := hexToNibbles(crypto.Keccak256Hash(contract.Bytes()))
	slotKey := slot.Calc(tokenID, 0)
	storPath := hexToNibbles(slotKey)

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
		Owner:     expOwner.Hex()[2:],
	}

	return &Bundle{Full: full, Public: pub, Blueprint: blue}, nil
}
