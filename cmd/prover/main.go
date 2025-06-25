package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/witness"
)

// contextKey is a custom type for context keys to avoid conflicts
type contextKey string

const startTimeKey contextKey = "start"

func main() {
	var (
		rpcURL    string
		blockNum  uint64
		contractS string
		tokenID   uint64
		ownerS    string
		outDir    string
	)

	rootCmd := &cobra.Command{
		Use:   "prover",
		Short: "Generate Groth16 proof of BAYC ownership",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if rpcURL == "" {
				_ = godotenv.Load()
				rpcURL = os.Getenv("ALCHEMY_URL")
				if rpcURL == "" {
					return fmt.Errorf("--rpc flag or ALCHEMY_URL env var is required")
				}
			}

			contract := common.HexToAddress(contractS)
			owner := common.HexToAddress(ownerS)

			// -----------------------------------------------------------------
			// Witness bundle
			// -----------------------------------------------------------------
			bundle, err := witness.Build(
				context.Background(),
				rpcURL, blockNum, contract,
				new(big.Int).SetUint64(tokenID), owner,
			)
			if err != nil {
				return err
			}

			// -----------------------------------------------------------------
			// Circuit compile
			// -----------------------------------------------------------------
			cs, err := frontend.Compile(
				circuits.Curve().ScalarField(),
				r1cs.NewBuilder,
				&circuits.BaycOwnershipCircuit{},
			)
			if err != nil {
				return err
			}

			// -----------------------------------------------------------------
			// Trusted setup (cached)
			// -----------------------------------------------------------------
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			pkPath := filepath.Join(outDir, "bayc_pk.bin")
			vkPath := filepath.Join(outDir, "bayc_vk.bin")

			var pk groth16.ProvingKey
			var vk groth16.VerifyingKey

			if pkBytes, err := os.ReadFile(pkPath); err == nil {
				_, _ = pk.ReadFrom(bytes.NewReader(pkBytes))
				vkBytes, _ := os.ReadFile(vkPath)
				_, _ = vk.ReadFrom(bytes.NewReader(vkBytes))
			} else {
				pk, vk, err = groth16.Setup(cs)
				if err != nil {
					return err
				}
				var b bytes.Buffer
				_, _ = pk.WriteTo(&b)
				_ = os.WriteFile(pkPath, b.Bytes(), 0o644)
				b.Reset()
				_, _ = vk.WriteTo(&b)
				_ = os.WriteFile(vkPath, b.Bytes(), 0o644)
			}

			// -----------------------------------------------------------------
			// Prove
			// -----------------------------------------------------------------
			proof, err := groth16.Prove(cs, pk, bundle.Full)
			if err != nil {
				return err
			}

			// -----------------------------------------------------------------
			// Outputs
			// -----------------------------------------------------------------
			proofPath := filepath.Join(outDir, "bayc_proof.bin")
			publicPath := filepath.Join(outDir, "bayc_public.json")

			var buf bytes.Buffer
			_, _ = proof.WriteTo(&buf)
			_ = os.WriteFile(proofPath, buf.Bytes(), 0o644)

			jsonBytes, _ := json.MarshalIndent(bundle.Public, "", "  ")
			_ = os.WriteFile(publicPath, jsonBytes, 0o644)

			csBuf := new(bytes.Buffer)
			_, _ = cs.WriteTo(csBuf)
			sum := sha256.Sum256(csBuf.Bytes())
			fmt.Printf("circuit hash: %x\n", sum[:4])
			fmt.Printf("proof done in %s\n", time.Since(cmd.Context().Value(startTimeKey).(time.Time)))
			return nil
		},
	}

	rootCmd.Flags().StringVar(&rpcURL, "rpc", "", "Alchemy archive RPC URL")
	rootCmd.Flags().Uint64Var(&blockNum, "block", 0, "Block number")
	rootCmd.Flags().StringVar(&contractS, "contract", "", "NFT contract address")
	rootCmd.Flags().Uint64Var(&tokenID, "tokenId", 0, "Token ID")
	rootCmd.Flags().StringVar(&ownerS, "owner", "", "Expected owner address")
	rootCmd.Flags().StringVar(&outDir, "outdir", "./", "Output directory")

	rootCmd.SetContext(context.WithValue(context.Background(), startTimeKey, time.Now()))
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}