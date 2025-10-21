# nftbk

[![CI](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml/badge.svg)](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml)[![Coverage](https://coveralls.io/repos/github/0xmichalis/nftbk/badge.svg?branch=main)](https://coveralls.io/github/0xmichalis/nftbk?branch=main)

A library, server, and CLI tool for protecting NFTs. The following networks are currently supported:
- EVM (Ethereum, Base, Shape, Zora, etc)
- Tezos

## Requirements

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs
- IPFS pinning service (optional)
- PostgreSQL (server-specific; used for backup metadata storage)

## Configuration

The application uses a unified configuration file that combines all settings:

- `config.toml`: Unified configuration file containing:
  - Chain RPC URLs
  - JWT authentication credentials (optional)
  - x402 payment configuration (optional)
  - IPFS pinning providers (optional)
- `config_tokens.toml`: Contains the NFT tokens to back up

The unified config includes prepopulated RPCs for various chains. Alchemy RPCs are used for EVM chains with an API key that can be configured as `ALCHEMY_API_KEY` inside an `.env` file. You can also choose to use different RPCs altogether. For `config_tokens.toml`, there is an `example_config_tokens.toml` that you can update as needed with the tokens to backup.

### Unified Configuration Structure

The `config.toml` file combines all configuration sections:

```toml
# Chain configurations (RPC endpoints)
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
polygon = "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
tezos = "https://mainnet.smartpy.io"

# JWT authentication credentials (optional)
[[jwt]]
issuer = "privy.io"
audience = "youraudience"
verification_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# x402 payment configuration (optional)
[x402]
asset_symbol = "USDC"
base_url = "https://localhost:8080/"
recipient_address = "0xYourRecipientAddress"
max_timeout_seconds = 300

[x402.facilitator]
url = "https://facilitator.payai.network"
network = "base"

# IPFS pinning providers (optional)
[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"

[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
bearer_token_env = "PINATA_TOKEN"
```

### Generate config from gallery.so

If you already have a [Gallery](https://gallery.so) account and gallery, you can easily create a backup of it by following these steps:
1. Note down the username and gallery id you want to back up. The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:
```sh
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

### JWT authentication support

The server supports authenticating JWT tokens using the unified configuration file. Multiple JWT credential sets can be configured in the `[[jwt]]` section.

Example JWT configuration in `config.toml`:

```toml
[[jwt]]
# Expected issuer (iss)
issuer = "https://issuer.example.com"
# Expected audience (aud)
audience = "my-audience"
# ES256 public key in PEM format (you may escape newlines as \n)
verification_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"

# Additional JWT credential sets can be added
[[jwt]]
issuer = "https://another-issuer.example.com"
audience = "another-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
```

All credential sets in the file are considered valid and tried during authentication.

### IPFS Pinning

There is support for pinning IPFS content using multiple providers. Both the [IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/) and the [Pinata API](https://docs.pinata.cloud/api-reference/introduction) are currently supported. 

Both the server and CLI can be configured to pin CIDs on IPFS via the unified configuration file. Example IPFS configuration in `config.toml`:

```toml
# Pin to Filebase (supports the IPFS Pinning Service API)
[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"

# Pin to Pinata
[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
bearer_token_env = "PINATA_TOKEN"
```

## Run

### CLI

Check the supported options in the CLI:

```sh
./target/debug/nftbk-cli --help
```

A few useful targets in the Makefile:

```sh
# Create a local backup based on config.toml and config_tokens.toml
make run-cli
# Request a backup from a local server running at localhost:8080 using tokens defined in config_tokens_test.toml
make run-cli-server-test 
```

### Postgres

Postgres is a requirement in order to run the server. Deploy Postgres and run migrations by following these instructions:

```sh
cp .env.postgres.example .env.postgres
# Fill out .env.postgres with your own credentials, etc.
# ...

# Run the database
make start-db

# Run migrations
export DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}
sqlx migrate run
```

### Server

```sh
# This deploys Postgres, runs the migrations, and finally runs the server
# You should have already created `.env.postgres` for this to work end to end.
make run

# If you are already running Postgres, you can simply run the server with:
make run-server
```

### OpenAPI Documentation

The server includes interactive OpenAPI documentation available at `/v1/swagger-ui` when running. This provides a complete API reference with example requests and responses for all endpoints. The OpenAPI specification JSON is available at `/v1/api-docs/openapi.json`.

Example usage:
```sh
# Start the server
make run-server

# View the interactive API documentation
open http://localhost:8080/v1/swagger-ui
```

## Contribute

```sh
# Install the pre-commit hook to aid with development
# The hook runs formatting, clippy, and tests
cp .hooks/pre-commit .git/hooks/pre-commit

# Update the sqlx cache and commit any changes when necessary - this is needed when developing
# new or updating existing static queries in the server.
make sqlxprepare

# Run tests with coverage output in HTML
make cover
```

## Donations

If you find this project helpful and would like to support its development, you can make a donation in the following addresses:
* Ethereum: `0xd2Be832911A252302bAc09e30Fc124A405E142DF` (michalis.eth)
* Tezos: `tz1ioFzpKGdwtncBkGunkUD9Sk16NqB2vML6` (michalis.tez)
