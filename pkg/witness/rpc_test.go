package witness

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
)

/* ---------------- little helper ---------------- */

func mustOpen(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		panic(err) // safe in tests
	}
	return f
}

/* ---------------- fixture server ---------------- */

func serveFixture(t *testing.T, filename string) *httptest.Server {
	t.Helper()

	body, err := io.ReadAll(mustOpen("testdata/" + filename))
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

/* ---------------- tests ---------------- */

func TestFetchStateRoot(t *testing.T) {
	srv := serveFixture(t, "header_22566332.json")
	defer srv.Close()

	cli, err := ethclient.Dial(srv.URL)
	require.NoError(t, err)

	root, err := FetchStateRoot(context.Background(), cli, 22566332)
	require.NoError(t, err)

	var hdr struct {
		Result struct{ Root common.Hash } `json:"result"`
	}
	require.NoError(t, json.NewDecoder(
		mustOpen("testdata/header_22566332.json")).Decode(&hdr))

	require.Equal(t, hdr.Result.Root, root)
}

func TestFetchProof(t *testing.T) {
	srv := serveFixture(t, "proof_bayc_8822.json")
	defer srv.Close()

	cli, _ := ethclient.Dial(srv.URL)

	slot     := common.HexToHash("0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5")
	contract := common.HexToAddress("0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d")

	p, err := FetchProof(context.Background(), cli, contract, slot, 22566332)
	require.NoError(t, err)
	require.Len(t, p.AccountProof, 10) // root→leaf path length on main-net today
}