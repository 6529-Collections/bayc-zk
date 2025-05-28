package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/witness"
)

func main() {
	var proofPath, publicPath, vkPath, rpcURL string

	cmd := &cobra.Command{
		Use:   "verifier",
		Short: "Verify Groth16 proof of BAYC ownership",
		RunE: func(cmd *cobra.Command, args []string) error {
			//------------------------------------------------------------------
			// Load artefacts
			//------------------------------------------------------------------
			pBytes, _ := os.ReadFile(proofPath)
			vBytes, _ := os.ReadFile(vkPath)
			jBytes, _ := os.ReadFile(publicPath)

			var proof groth16.Proof
			_, _ = proof.ReadFrom(bytes.NewReader(pBytes))

			var vk groth16.VerifyingKey
			_, _ = vk.ReadFrom(bytes.NewReader(vBytes))

			var pub witness.PublicInputs
			_ = json.Unmarshal(jBytes, &pub)

			//------------------------------------------------------------------
			// Optional stateRoot sanity
			//------------------------------------------------------------------
			if rpcURL != "" {
				_ = godotenv.Load()
				// fetch block header and compare – left as exercise
			}

			//------------------------------------------------------------------
			// Public witness
			//------------------------------------------------------------------
			pubAssign := &circuits.BaycOwnershipCircuit{
				StateRoot: pub.StateRoot,
				TokenID:   pub.TokenID,
				Owner:     pub.Owner,
			}
			pubWit, _ := frontend.NewWitness(
				pubAssign,
				circuits.Curve().ScalarField(),
				frontend.PublicOnly(),
			)

			//------------------------------------------------------------------
			// Verify
			//------------------------------------------------------------------
			if err := groth16.Verify(proof, vk, pubWit); err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			fmt.Println("proof verified ✅")
			return nil
		},
	}

	cmd.Flags().StringVar(&proofPath, "proof", "", "bayc_proof.bin")
	cmd.Flags().StringVar(&publicPath, "public", "", "bayc_public.json")
	cmd.Flags().StringVar(&vkPath, "vk", "", "bayc_vk.bin")
	cmd.Flags().StringVar(&rpcURL, "rpc", "", "Optional RPC for stateRoot check")
	_ = cmd.MarkFlagRequired("proof")
	_ = cmd.MarkFlagRequired("public")
	_ = cmd.MarkFlagRequired("vk")

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		log.Fatal(err)
	}
}