# nftbk

CLI tool for backing up NFT metadata and content for Ethereum and Tezos accounts.

## Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Ethereum RPC URL (e.g., from [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/))

## Building

```bash
cargo build --release
```

## Development

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --all -- --check

# Run clippy lints
cargo clippy -- -D warnings

# Run tests
cargo test
```

## Usage

1. Set your Ethereum RPC URL:
```bash
export ETH_RPC_URL='your-ethereum-rpc-url'
```

2. Run the tool:
```bash
# Basic usage with specific NFT contracts
./target/release/nftbk 0x123... --nft-contracts 0xabc...,0xdef...

# With custom backup path
./target/release/nftbk 0x123... --nft-contracts 0xabc... --path /backup/path

# Multiple addresses
./target/release/nftbk 0x123... tz1abc... --nft-contracts 0xdef...
```

## Output Structure

```
backup_path/
  └── contract_address/
      └── token_id/
          ├── metadata.json
          ├── image.*
          └── animation.*
```
