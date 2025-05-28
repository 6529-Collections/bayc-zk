# bayc‑zk

> **Zero‑Knowledge Proof of BAYC #8822 ownership at Ethereum main‑net block 22566332.**
>
> *Status: bootstrap skeleton — circuit & witness logic to be completed.*

## Quick start
```bash
# Clone and build
$ git clone https://github.com/your‑org/bayc‑zk.git && cd bayc‑zk
$ make build

# Run prover (requires ALCHEMY_URL env var or --rpc)
$ ./bin/prover \
  --block 22566332 \
  --contract 0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d \
  --tokenId 8822 \
  --owner 0xc7626d18d697913c9e3ab06366399c7e9e814e94 \
  --outdir examples/22566332

# Run verifier (offline)
$ ./bin/verifier \
  --proof examples/22566332/bayc_proof.bin \
  --public examples/22566332/bayc_public.json \
  --vk examples/22566332/bayc_vk.json