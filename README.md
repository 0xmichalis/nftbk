# nftbk

A library, server, and CLI tool for backing up NFT metadata and content from EVM and Tezos NFT contracts.

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs

## Configuration

Two configuration files are used:
- `config_chains.toml`: Contains RPC URLs for different chains
- `config_tokens.toml`: Contains the NFT tokens to back up

Currently `config_chains.toml` includes a few prepopulated RPCs and for Ethereum specifically, you would need to use an Alchemy API key that can be configured as `ETH_RPC_API_KEY` inside an `.env` file. Or choose to use a different RPC altogether. For `config_tokens.toml`, there is an `example_config_tokens.toml` that you can update as needed with the tokens to backup.

### Generate config from gallery.so

If you already have a [Gallery](https://gallery.so) account and gallery, you can easily create a backup of it by following these steps:
1. Note down the username and gallery id you want to back up. The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:
```bash
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

## Run

To run the CLI:

```
cargo run --bin nftbk-cli -- [args]
```

To run the server:

```
cargo run --bin nftbk-server -- [args]
```
