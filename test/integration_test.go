// test/integration_test.go
package test

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/bayczk/circuits"
	wit "github.com/yourorg/bayczk/pkg/witness"
)

func rpcFixtureServer(tb testing.TB) *httptest.Server {
	tb.Helper()

	type req struct{ Method string }

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q req
		_ = json.NewDecoder(r.Body).Decode(&q)

		var file string
		switch q.Method {
		case "eth_getBlockByNumber":
			file = "header_latest.json"
		case "eth_getProof":
			file = "proof_doodles_8822.json"
		default:
			http.Error(w, "unsupported method", http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r,
			filepath.Join("..", "pkg", "witness", "testdata", file))
	}))
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in –short")
	}
	
	// Stress-testing with full Doodles proof to measure constraint explosion
	t.Logf("Running stress test with universal rlpListWalk verification")

	srv := rpcFixtureServer(t)
	defer srv.Close()

	ctx      := context.Background()
	blockNum := uint64(0)  // Latest block (using 0 as placeholder since we use "latest")
	contract := common.HexToAddress("0x8a90cab2b38dba80c64b7734e58ee1db38b8992e") // Doodles
	tokenID  := big.NewInt(8822)
	owner    := common.HexToAddress("0x4D892DB983E659317F82f3c91f26026D92E40B89") // Real owner from Doodles storage proof

	bdl, err := wit.Build(ctx, srv.URL, blockNum, contract, tokenID, owner)
	require.NoError(t, err)

	t.Logf("Starting circuit compilation...")
	cs, err := frontend.Compile(
		circuits.Curve().ScalarField(),
		r1cs.NewBuilder,
		bdl.Blueprint)
	require.NoError(t, err)
	
	// Profile constraint count
	t.Logf("Circuit compiled successfully with %d constraints", cs.GetNbConstraints())

	// Debug witness solving with detailed error information
	t.Logf("Testing witness solving...")
	err = cs.IsSolved(bdl.Full)
	if err != nil {
		t.Logf("Witness solving failed: %v", err)
		
		// Let's examine the witness values
		t.Logf("Debugging witness structure...")
		t.Logf("Public inputs: %+v", bdl.Public)
		t.Logf("Expected owner length: %d", len(bdl.Blueprint.ExpectedOwner))
		t.Logf("Storage proof nodes: %d", len(bdl.Blueprint.StorageProof))
		
		// Fail with detailed error
		require.NoError(t, err)
	}
	
	t.Logf("Witness solving succeeded!")

	blob, err := bdl.Full.MarshalBinary()
	require.NoError(t, err)

	badFull, err := bw.New(circuits.Curve().ScalarField())
	require.NoError(t, err)
	require.NoError(t, badFull.UnmarshalBinary(blob))

	switch v := badFull.Vector().(type) {
	case fr.Vector:
		v[0].SetUint64(v[0].Uint64() ^ 1)

	case *fr.Vector:
		(*v)[0].SetUint64((*v)[0].Uint64() ^ 1)

	default:
		t.Fatalf("unexpected vector type %T", v)
	}

	require.Error(t, cs.IsSolved(badFull))
}