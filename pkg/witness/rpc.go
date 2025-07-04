package witness

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Proof struct {
	AccountProof []string `json:"accountProof"`
	StorageProof []struct {
		Key   string   `json:"key"`
		Value string   `json:"value"`
		Proof []string `json:"proof"`
	} `json:"storageProof"`
	StorageHash string `json:"storageHash"`
	CodeHash    string `json:"codeHash"`
	Balance     string `json:"balance"`
	Nonce       string `json:"nonce"`
}

func FetchProof(
	ctx context.Context,
	cli *ethclient.Client,
	contract common.Address,
	slotKey common.Hash,
	block uint64,
) (*Proof, error) {

	var p Proof
	err := cli.Client().CallContext(
		ctx, &p, "eth_getProof",
		contract,
		[]string{slotKey.Hex()},
		hexutil.Uint64(block),
	)
	return &p, err
}

func FetchStateRoot(ctx context.Context, cli *ethclient.Client, block uint64) (common.Hash, error) {
	hexNum := hexutil.Uint64(block)
	var hdr struct {
		StateRoot string `json:"stateRoot"`
	}
	if err := cli.Client().CallContext(ctx, &hdr, "eth_getBlockByNumber", hexNum, false); err != nil {
		return common.Hash{}, err
	}
	return common.HexToHash(hdr.StateRoot), nil
}
