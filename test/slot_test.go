package test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/bayczk/pkg/slot"
)

func TestSlotKeyVectors(t *testing.T) {
	vec := []struct {
		id   string
		tid  *big.Int
		want string
	}{
		{"zero", big.NewInt(0), "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"},
		{"one", big.NewInt(1), "0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d"},
		{"max", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
			"0xbbd6e7dddd4326dd7c827841ab9733c6e3fcdf38a516374bd10feec8f674ea8a"},
	}

	for _, v := range vec {
		got := slot.Calc(v.tid, 0)
		require.Equal(t, v.want, hexutil.Encode(got[:]), v.id)
	}
}
