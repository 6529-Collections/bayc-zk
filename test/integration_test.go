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

/* ──────────────── tiny fixture RPC server ──────────────── */

func rpcFixtureServer(tb testing.TB) *httptest.Server {
	tb.Helper()

	type req struct{ Method string }

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q req
		_ = json.NewDecoder(r.Body).Decode(&q)

		var file string
		switch q.Method {
		case "eth_getBlockByNumber":
			file = "header_22566332.json"
		case "eth_getProof":
			file = "proof_bayc_8822.json"
		default:
			http.Error(w, "unsupported method", http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r,
			filepath.Join("..", "pkg", "witness", "testdata", file))
	}))
}

/* ───────────────────────── e2e test ─────────────────────── */

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skip e2e in –short")
	}

	srv := rpcFixtureServer(t)
	defer srv.Close()

	ctx      := context.Background()
	blockNum := uint64(22566332)
	contract := common.HexToAddress("0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d")
	tokenID  := big.NewInt(8822)
	owner    := common.HexToAddress("0xc7626d18d697913c9e3ab06366399c7e9e814e94")

	/* ---------- witness bundle -------------------------------------- */
	bdl, err := wit.Build(ctx, srv.URL, blockNum, contract, tokenID, owner)
	require.NoError(t, err)

	/* ---------- compile circuit ------------------------------------- */
	cs, err := frontend.Compile(
		circuits.Curve().ScalarField(),
		r1cs.NewBuilder,
		bdl.Blueprint, // blueprint only fixes slice lengths
	)
	require.NoError(t, err)

	/* ---------- 1) good witness passes ------------------------------ */
	require.NoError(t, cs.IsSolved(bdl.Full))

	/* ---------- 2) clone witness, flip 1 owner-byte ----------------- */

	blob, err := bdl.Full.MarshalBinary()
	require.NoError(t, err)

	badFull, err := bw.New(circuits.Curve().ScalarField())
	require.NoError(t, err)
	require.NoError(t, badFull.UnmarshalBinary(blob))

	switch vecAny := badFull.Vector().(type) {

	case fr.Vector: // value slice
		ownerStart := len(vecAny) - 32
		vecAny[ownerStart].SetUint64(vecAny[ownerStart].Uint64() ^ 1)

	case *fr.Vector: // pointer slice
		ownerStart := len(*vecAny) - 32
		(*vecAny)[ownerStart].SetUint64((*vecAny)[ownerStart].Uint64() ^ 1)

	default:
		t.Fatalf("unexpected vector type %T", vecAny)
	}

	/* ---------- 3) corrupted witness must fail ---------------------- */
	require.Error(t, cs.IsSolved(badFull))
}