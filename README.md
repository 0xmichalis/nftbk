# nftbk

CLI tool for backing up NFT metadata and content from Ethereum and Tezos NFT contracts.

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs

## Configuration

Copy `config.example.toml` to `config.toml` file and update as needed.

Example config:
```toml
[chains]
ethereum = "https://mainnet.infura.io/v3/your_key"
tezos = "https://mainnet.smartpy.io"

[tokens]
ethereum = [
    "0x3D7E6A293C5ca4cD6721Df1A99683802331793C7:26",
    "0x1D8629438f0Ce0DE787D48BEb3F153884B2F370d:12"
]
tezos = [
    "KT1DmEFfeqEC3nEx6bpWKqjNY8FF8RFrR3Gc:28"
]
```

## Usage

```bash
cargo run
```

## Output Structure

All content is saved in an `nft_backup` directory within the specified output path:

```
nft_backup/
  ├── ethereum/
  │   └── contract_address/
  │       └── token_id/
  │           ├── artifact.*
  │           └── metadata.json
  └── tezos/
      └── contract_address/
          └── token_id/
              ├── artifact.*
              └── metadata.json
```

## Contribute

```bash
# Build code
cargo build

# Format code
cargo fmt --all

# Run clippy lints
cargo clippy -- -D warnings

# Run tests
cargo test
```
