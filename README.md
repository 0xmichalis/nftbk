# nftbk

CLI tool for backing up NFT metadata and content from Ethereum and Tezos NFT contracts.

_Built with the use of [Cline](https://github.com/cline/cline) + [OpenRouter](https://openrouter.ai/) (Claude Sonnet 3.5, DeepSeek)._

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Ethereum RPC URL (e.g., from [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/))

## Configuration

1. Create a `config.toml` file (or copy from `config.toml.example`) to specify which NFT contracts and token IDs to backup:

```toml
[contracts]
# Ethereum contracts in format: "contract_address:token_id"
ethereum = [
    "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1",  # BAYC #1
    "0x60e4d786628fea6478f785a6d7e704777c86a7c6:2"   # MAYC #2
]

# Tezos contracts (coming soon)
tezos = []
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
