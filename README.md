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

### Generate config from gallery.so

1. Note down the username and gallery id you want to back up from [gallery.so](https://gallery.so). The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:
```bash
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config.toml
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

Copy the pre-commit hook to .git/hooks/pre-commit:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
```

Now `make all` will run everytime you commit. Otherwise, you can run it manually:

```bash
make all
```
