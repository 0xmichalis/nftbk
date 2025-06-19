# nftbk

CLI tool for backing up NFT metadata and content from Ethereum and Tezos NFT contracts.

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs

## Configuration

Two configuration files are used:
- `config_chains.toml`: Contains RPC URLs for different chains
- `config_tokens.toml`: Contains the NFT tokens to back up

Copy `config.example.chains.toml` to `config_chains.toml` and `config.example.tokens.toml` to `config_tokens.toml`, then update as needed.

Example configs:

`config_chains.toml`:
```toml
ethereum = "https://mainnet.infura.io/v3/your_key"
tezos = "https://mainnet.smartpy.io"
```

`config_tokens.toml`:
```toml
ethereum = [
    "0x3D7E6A293C5ca4cD6721Df1A99683802331793C7:26",
    "0x1D8629438f0Ce0DE787D48BEb3F153884B2F370d:12"
]
tezos = [
    "KT1DmEFfeqEC3nEx6bpWKqjNY8FF8RFrR3Gc:28"
]
```

### Generate config from gallery.so

1. Note down the username and gallery id you want to back up from [gallery.so](https://gallery.so). The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
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
