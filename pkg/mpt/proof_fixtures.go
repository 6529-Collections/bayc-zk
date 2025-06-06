// +build test

package mpt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/std/math/uints"
)

type rawFixture struct {
	Root    string   `json:"root"`
	Path    string   `json:"path"`   // hex nibble string (even length)
	Leaf    string   `json:"leaf"`   // 32-byte account payload
	Nodes   []string `json:"nodes"`  // RLP-encoded, root … leaf
}

type branchVec struct {
	root    []uints.U8
	path    []uints.U8
	nodes   [][]uints.U8
	payload []uints.U8
}

// test helper – panics on error (only used in tests)
func mustLoadFixtures(t *testing.T) branchVec {
	file := filepath.Join("testdata", "proof_bayc_8822.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var fx rawFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	hex2U8s := func(s string) []uints.U8 {
		b, _ := hex.DecodeString(s)
		return BytesToU8s(b)
	}

	vec := branchVec{
		root:    hex2U8s(fx.Root),
		path:    hex2U8s(fx.Path),
		payload: hex2U8s(fx.Leaf),
		nodes:   make([][]uints.U8, len(fx.Nodes)),
	}
	for i, n := range fx.Nodes {
		vec.nodes[i] = hex2U8s(n)
	}
	return vec
}