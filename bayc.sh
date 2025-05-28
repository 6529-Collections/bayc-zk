#!/usr/bin/env bash
set -euo pipefail

BLOCK=22566332
CONTRACT=0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d   # BAYC
TOKEN_ID=8822                                         # decimal

# ------------------------------------------------------------------ #
# 1) calculate storage-slot key = keccak256(pad32(tokenId) || pad32(0))
# ------------------------------------------------------------------ #

PAD_ID=$(cast --to-uint256 $TOKEN_ID | cut -c3-)   # strip "0x", 64 hex chars
SLOT_KEY=$(cast keccak 0x${PAD_ID}0000000000000000000000000000000000000000000000000000000000000000)
echo "slotKey = $SLOT_KEY"

# ------------------------------------------------------------------ #
# 2) fetch fixtures once and save under pkg/witness/testdata/
# ------------------------------------------------------------------ #

RPC=${ALCHEMY_URL:-https://eth-mainnet.alchemyapi.io/v2/$ALCHEMY_API_KEY}

# Header (stateRoot comes from here)
curl -s -X POST "$RPC" \
  -d @- <<EOF | jq . >pkg/witness/testdata/header_${BLOCK}.json
{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x$(printf '%x' $BLOCK)",false]}
EOF

# eth_getProof for BAYC token 8822
curl -s -X POST "$RPC" \
  -d @- <<EOF | jq . >pkg/witness/testdata/proof_bayc_${TOKEN_ID}.json
{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["$CONTRACT",["$SLOT_KEY"],"0x$(printf '%x' $BLOCK)"]}
EOF