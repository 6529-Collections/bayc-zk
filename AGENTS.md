The spec of the whole program:

---

## Specification

### Zero-Knowledge Proof of BAYC #8822 Ownership at Block 22566332

**Version 1.0 — 26 May 2025**

---

### 0  Purpose

Deliver two small Go binaries:

| Component      | Goal                                                                                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`prover`**   | Produces a Groth16 proof (via gnark) that BAYC token `8822` was owned by wallet `0xc762…4e94` in Ethereum block `22566332`; all facts are fetched exclusively from an Alchemy archive RPC. |
| **`verifier`** | Replays the proof with (a) the verifying key and (b) at most one fresh RPC call, confirming the claim without trusting the prover’s node.                                                  |

The binaries plus their output files let any third-party confirm ownership offline.

---

### 1  System Context

```
┌─────────────┐
│ Alchemy RPC │  ← eth_getBlock, eth_getProof
└──────┬──────┘
       │ JSON-RPC
┌──────▼──────┐        PK + witness → proof
│   prover    │──────────────────────────────┐
└──────┬──────┘                              │
       │ writes                              │
       ▼                                     ▼
  bayc_proof.bin   bayc_public.json   bayc_vk.json
       ▲                                     │
┌──────┴──────┐      verify( proof, vk, public )
│  verifier   │────────────────────────────────┘
└─────────────┘
```

---

### 2  Functional Requirements

| ID      | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **F-1** | `prover` shall accept `--rpc`, `--block`, `--contract`, `--tokenId`, `--owner`, `--outdir`.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **F-2** | `prover` shall: <br>  a. Fetch block header → extract `stateRoot`.<br>  b. Derive storage-slot key for `_owners[tokenId]` (BAYC uses slot 0).<br>  c. Call `eth_getProof` with (\[contractAddr], \[storageSlot], blockTag).<br>  d. Build a gnark witness embedding: `accountProof`, `storageProof`, `stateRoot`, `tokenId`, `ownerAddr`.<br>  e. Generate Groth16 proof; write:<br>    • `bayc_proof.bin` (binary)<br>    • `bayc_public.json` (stateRoot, tokenId, owner)<br>    • `bayc_vk.json` (if not already present). |
| **F-3** | `verifier` shall accept `--proof`, `--public`, `--vk` plus optional `--rpc`.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **F-4** | `verifier` shall: <br>  a. Load verifying key and public inputs.<br>  b. If `--rpc` supplied, fetch block N and cross-check `stateRoot`.<br>  c. Run `gnark.Verify` → exit 0 on success, non-zero on failure.                                                                                                                                                                                                                                                                                                                 |
| **F-5** | Both binaries must finish under 30 s on a laptop with 16 GB RAM.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

---

### 3  Non-Functional Requirements

* **N-1 Language** Go 1.22 or later; `go mod` for deps.
* **N-2 Libraries** `github.com/consensys/gnark/v1`, `github.com/ethereum/go-ethereum` (RLP & trie utils), `github.com/joho/godotenv` (optional).
* **N-3 Security** No hard-coded secrets; RPC URL read from flag or `ALCHEMY_URL`.
* **N-4 Determinism** Given the same inputs, output files must be byte-identical.
* **N-5 Artifact sizes** Proof < 1 kB; verifying key < 150 kB.

---

### 4  Circuit Specification (`bayc_ownership.circom.go`)

| Item               | Value                                                                                                                                                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Proving system** | Groth16 (SHA-256 transcript).                                                                                                                                                                                                         |
| **Public inputs**  | `stateRoot [32]byte`, `tokenId uint256`, `owner uint256`.                                                                                                                                                                             |
| **Witness**        | <ul><li>`accountProof`: list of RLP-encoded world-state nodes from root → BAYC account (≤ 9 for main-net).</li><li>`storageProof`: list of RLP-encoded storage-trie nodes from account.storageRoot → leaf.</li></ul>                  |
| **Constraints**    | <ol><li>Keccak-256 hash gadget over each RLP node → parent pointer check.</li><li>MPT branch verification (path nibble checks).</li><li>Leaf value equals `owner`.</li><li>Key equals `keccak256(pad32(tokenId)‖pad32(0))`.</li></ol> |
| **Complexity**     | ≈ 220 k constraints; compile & setup < 10 s.                                                                                                                                                                                          |

> *Rationale:* entire Merkle-Patricia verification inside ZK removes need for the verifier to download trie nodes.

---

### 5  Development Approach

| Phase                                | Deliverable                                                                          | Tips / Tooling                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| **P-0   Bootstrap**                  | `go mod init bayc-zk`<br>`makefile` with `lint`, `test`, `build`, `release` targets. | Use `golangci-lint`, `.editorconfig`.                                  |
| **P-1   Circuit MVP**                | Hard-code small dummy trie; compile & verify in-process tests.                       | Start constraint coding in pure Go DSL before wiring CLI.              |
| **P-2   Slot calc / `eth_getProof`** | Unit tests: compare computed slot key to `cast storage` outputs.                     | Mock RPC via Go-Ethereum’s `rpc/ethclient`.                            |
| **P-3   Witness builder**            | `pkg/witness/builder.go` with pure Go struct, (de)serialisers.                       | Keep node order identical to RPC response to simplify path validation. |
| **P-4   Prover CLI**                 | `cmd/prover/main.go` + Cobra flags; integration test hitting Alchemy.                | Cache verifying key; allow `--pk` override for benchmarking.           |
| **P-5   Verifier CLI**               | `cmd/verifier/main.go`; golden-file tests (positive & negative).                     | Stub out RPC in CI to avoid external calls.                            |
| **P-6   Docs & Release**             | `README.md`, `SPEC.md` (this doc), `LICENSE`.                                        | Produce versioned tarball + pre-built binaries.                        |

---

### 6  Directory Layout

```
bayc-zk/
├── cmd/
│   ├── prover/
│   │   └── main.go
│   └── verifier/
│       └── main.go
├── circuits/
│   └── bayc_ownership.go
├── pkg/
│   ├── witness/
│   │   ├── builder.go
│   │   └── types.go
│   └── mpt/
│       └── verify.go   (re-usable constraint helpers)
├── internal/
│   └── keccak/         (if you wrap gnark’s gadget)
├── test/
│   ├── slot_test.go
│   ├── mpt_test.go
│   └── integration_test.go
├── makefile
└── go.mod
```

---

### 7  Testing Matrix

| Layer           | Cases                                                                                                                                                   |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unit**        | *Slot key:* ids `0, 1, 8822, 2²⁵⁶-1`.<br>*Keccak gadget:* random vectors.<br>*RLP parsing:* valid / bad length / bad hex.                               |
| **Integration** | *Happy path:* live block 22566332.<br>*Wrong owner:* mutate `public.json` owner field → verify fails.<br>*Wrong block:* use block 22566333 `stateRoot`. |
| **E2E CI**      | Run prover against a **mock** rpc fixture → generate proof → verify. CI must not depend on external network.                                            |

---

### 8  Dependencies & Versions

| Library     | Min Version | Reason                                         |
| ----------- | ----------- | ---------------------------------------------- |
| Go          | 1.22        | generics, slices-in-maps fix                   |
| gnark       | v1.10       | Groth16 API stabilised, built-in Keccak gadget |
| go-ethereum | v1.14       | RLP & Trie path verifier used in tests         |
| Cobra       | v1.7        | ergonomics for CLI flags                       |

---

### 9  Security & Audit Notes

1. **Trusted Setup** — include SHA-256 of `bayc_circuit.r1cs` in the repository; regenerate PK/VK only when the circuit hash changes.
2. **RPC Spoofing** — verifier fetches only the block header; a malicious prover cannot fake a `stateRoot` that matches both header and trie unless they break SHA-256 + Keccak assumptions.
3. **Replay** — public inputs embed block number; always display it in CLI output to prevent time-based confusion.
4. **Side-Channels** — proof generation is offline; no secrets handled after witness building.

---

### 10  Deliverables

1. **Source repo** as per § 6.
2. `prover` & `verifier` statically linked Linux/amd64 binaries.
3. Pre-generated `bayc_vk.json` committed.
4. Example proof set in `examples/22566332/`.
5. Build instructions (`README.md`).
6. Test report (`coverage.html`, GitHub Actions log).

---

### 11  Acceptance Criteria

* Running

  ```bash
  ./prover --rpc $ALCHEMY --block 22566332 \
           --contract 0xbc4c...f13d --tokenId 8822 \
           --owner 0xc762...4e94 --outdir examples/22566332
  ```

  must finish < 30 s and produce three files.
* `./verifier --proof .../proof.bin --public .../public.json --vk .../vk.json`
  must exit 0 and print **“proof verified”**.
* Negative tests (wrong owner, wrong block) must fail.
* CI passes on a clean checkout with `go test ./...` and `make build`.

---

#### End of Specification
