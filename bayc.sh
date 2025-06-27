#!/usr/bin/env bash
set -euo pipefail

BLOCK=latest
CONTRACT=0x8a90cab2b38dba80c64b7734e58ee1db38b8992e   # Doodles
TOKEN_ID=8822                                         # decimal

# ------------------------------------------------------------------ #
# 1) calculate storage-slot key = keccak256(pad32(tokenId) || pad32(slot))
# Doodles uses OpenZeppelin standard: _owners mapping at slot 2
# ------------------------------------------------------------------ #

PAD_ID=$(cast --to-uint256 $TOKEN_ID)   # Keep "0x" prefix
SLOT_KEY=$(cast keccak ${PAD_ID}$(printf "%064x" 2))  # Slot 2 for _owners mapping
echo "slotKey = $SLOT_KEY"

# ------------------------------------------------------------------ #
# 2) fetch fixtures once and save under pkg/witness/testdata/
# ------------------------------------------------------------------ #

RPC=${ALCHEMY_URL:-https://eth-mainnet.alchemyapi.io/v2/${ALCHEMY_API_KEY}}

# Header (stateRoot comes from here) 
curl -s -X POST "$RPC" \
  -d @- <<EOF | jq . >pkg/witness/testdata/header_latest.json
{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}
EOF

# eth_getProof for Doodles token 8822
curl -s -X POST "$RPC" \
  -d @- <<EOF | jq . >pkg/witness/testdata/proof_doodles_${TOKEN_ID}.json
{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["$CONTRACT",["$SLOT_KEY"],"latest"]}
EOF