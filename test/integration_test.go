package test

import (
	"os/exec"
	"testing"
)

// This integration test runs prover then verifier against a static RPC‑fixture
// recorded with go‑ethereum’s rpcdump.  Kept empty until the circuit is fully
// implemented to avoid CI flakiness.
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	_ = exec.Command("true").Run() // placeholder
}