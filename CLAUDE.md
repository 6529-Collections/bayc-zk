# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

- `make build` - Builds both prover and verifier binaries to `./bin/`
- `make test` - Runs all Go tests
- `make lint` - Runs golangci-lint on the codebase
- `make clean` - Removes binaries and generated proof files
- `go test ./pkg/mpt/...` - Run tests for specific package

## Architecture Overview

This is a zero-knowledge proof system for proving BAYC NFT ownership using Groth16 proofs and Ethereum Merkle Patricia Trie verification.

### Core Components

**Prover (`cmd/prover/main.go`)**
- Fetches Ethereum state proofs via RPC
- Compiles circuits using gnark
- Generates Groth16 proofs with cached trusted setup
- Outputs proof files and public inputs

**Verifier (`cmd/verifier/main.go`)**
- Verifies Groth16 proofs offline using saved verification keys

**Circuit (`circuits/bayc_ownership.go`)**
- Defines the BaycOwnershipCircuit with public inputs (StateRoot, TokenID)
- Currently implements account MPT verification; storage branch verification is planned
- Uses BN254 curve via gnark

**Witness Builder (`pkg/witness/builder.go`)**
- Constructs circuit witnesses from Ethereum RPC data
- Handles account and storage proof node conversion
- Manages nibble path encoding for MPT traversal

**MPT Package (`pkg/mpt/`)**
- `verify.go`: Core MPT branch verification logic with hashPtr and VerifyBranch
- `hash.go`, `rlp.go`: RLP encoding and Keccak hashing utilities
- Extensive test coverage with fixtures

### Data Flow

1. `bayc.sh` fetches block headers and storage proofs from Alchemy RPC
2. Prover builds witness from RPC data and compiles circuit
3. Circuit verifies account MPT branch from state root to account leaf
4. Storage branch verification is stubbed out (work in progress)
5. Groth16 proof generated and saved with public inputs

### Development Notes

- Uses gnark v0.12.0 for ZK circuits and Groth16 proofs
- Ethereum integration via go-ethereum v1.15.11
- Test data stored in `pkg/witness/testdata/` (block headers and proofs)
- Requires ALCHEMY_URL environment variable or --rpc flag for mainnet access
- Circuit currently incomplete - storage MPT verification not implemented yet

End goal and larger specification can be found in file SPEC.md