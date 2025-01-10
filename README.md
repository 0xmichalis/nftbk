# nftbk

CLI tool for backing up NFT metadata and content from Ethereum and Tezos NFT contracts.

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Ethereum RPC URL (e.g., from [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/))

## Configuration

1. Create a `config.toml` file (or copy from `config.toml.example`) to specify which NFT contracts and token IDs to backup:

```toml
# List of NFT contract addresses to fetch metadata and content from
[contracts]

# Tokens in format: "contract_address:token_id"
ethereum = [
    '0x3D7E6A293C5ca4cD6721Df1A99683802331793C7:26',
    '0x1D8629438f0Ce0DE787D48BEb3F153884B2F370d:12'
]
tezos = [
    'KT1DmEFfeqEC3nEx6bpWKqjNY8FF8RFrR3Gc:28'
]
```

2. Copy `.env` from `.env.example` and fill out as needed.
```bash
cp .env.example .env
# Update .env accordingly ...
```

## Usage

```bash
cargo run
```

## Output Structure

All content is saved in an `nft_backup` directory within the specified output path:

```
nft_backup/
  └── ethereum/
      └── contract_address/
          └── token_id/
              ├── metadata.json
              ├── image.*
              └── animation.*
```

## Contribute

```bash
# Build code
cargo build

# Format code
cargo fmt

# Check formatting
cargo fmt --all -- --check

# Run clippy lints
cargo clippy -- -D warnings

# Run tests
cargo test
```
