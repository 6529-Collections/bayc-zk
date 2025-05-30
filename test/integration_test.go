// test/integration_test.go
package test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/mpt"
	"github.com/yourorg/bayczk/pkg/witness"
)

/* -------------------------------------------------------------------------- */
/* tiny RPC server that replays the JSON fixtures                             */
/* -------------------------------------------------------------------------- */

func rpcFixtureServer(tb testing.TB) *httptest.Server {
	tb.Helper()

	type req struct{ Method string }

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q req
		_ = json.NewDecoder(r.Body).Decode(&q)

		var fn string
		switch q.Method {
		case "eth_getBlockByNumber":
			fn = "header_22566332.json"
		case "eth_getProof":
			fn = "proof_bayc_8822.json"
		default:
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r, filepath.Join("..", "pkg", "witness", "testdata", fn))
	}))
}

/* -------------------------------------------------------------------------- */
/* helper                                                                     */
/* -------------------------------------------------------------------------- */

func mustRead(tb testing.TB, p string) []byte {
	tb.Helper()
	b, err := os.ReadFile(p)
	require.NoError(tb, err)
	return b
}

/* -------------------------------------------------------------------------- */
/* E2E: witness ➜ compile ➜ solved?                                           */
/* -------------------------------------------------------------------------- */

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in short mode")
	}

	/* ---------- spin up mock RPC ------------------------------------ */
	srv := rpcFixtureServer(t)
	defer srv.Close()

	/* ---------- inputs ---------------------------------------------- */
	ctx      := context.Background()
	blockNum := uint64(22566332)
	contract := common.HexToAddress("0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d")
	tokenID  := big.NewInt(8822)
	owner    := common.HexToAddress("0xc7626d18d697913c9e3ab06366399c7e9e814e94")

	/* ---------- build witness bundle -------------------------------- */
	bdl, err := witness.Build(ctx, srv.URL, blockNum, contract, tokenID, owner)
	require.NoError(t, err)

	/* ---------- blueprint with correct slice lengths ---------------- */
	// Read the proof JSON once more – just for lengths
	var proof struct {
		Result struct {
			AccountProof []string `json:"accountProof"`
			StorageProof []struct{ Proof []string } `json:"storageProof"`
		} `json:"result"`
	}
	fixture := filepath.Join("..", "pkg", "witness", "testdata", "proof_bayc_8822.json")
	require.NoError(t, json.Unmarshal(mustRead(t, fixture), &proof))

	accBP := make([][]uints.U8, len(proof.Result.AccountProof))
	for i, s := range proof.Result.AccountProof {
		raw, _ := hex.DecodeString(s[2:])
		accBP[i] = make([]uints.U8, len(raw))
	}
	storBP := make([][]uints.U8, len(proof.Result.StorageProof[0].Proof))
	for i, s := range proof.Result.StorageProof[0].Proof {
		raw, _ := hex.DecodeString(s[2:])
		storBP[i] = make([]uints.U8, len(raw))
	}

	blueprint := circuits.BaycOwnershipCircuit{
		AccountProof: accBP,
		StorageProof: storBP,
		AccountPath:  make([]uints.U8, 64), // 32-byte keccak → 64 nibbles
		StoragePath:  make([]uints.U8, 64),
		OwnerBytes:   make([]uints.U8, 20),
	}

	/* ---------- compile & solve ------------------------------------- */
	cs, err := frontend.Compile(
		circuits.Curve().ScalarField(),
		r1cs.NewBuilder,
		&blueprint,
	)
	require.NoError(t, err)

	require.NoError(t, cs.IsSolved(bdl.Full))
}

/* -------------------------------------------------------------------------- */
/* (unused) converts raw bytes to []uints.U8 – kept for possible extensions   */
/* -------------------------------------------------------------------------- */
func u8Slice(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b {
		out[i] = mpt.ConstU8(v)
	}
	return out
}