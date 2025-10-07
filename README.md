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

Two configuration files are used:
- `config_chains.toml`: Contains RPC URLs for different chains
- `config_tokens.toml`: Contains the NFT tokens to back up

Currently `config_chains.toml` includes a few prepopulated RPCs. Alchemy RPCs are used for EVM chains with an API key that can be configured as `ALCHEMY_API_KEY` inside an `.env` file. You can also choose to use different RPCs altogether. For `config_tokens.toml`, there is an `example_config_tokens.toml` that you can update as needed with the tokens to backup.

### Generate config from gallery.so

If you already have a [Gallery](https://gallery.so) account and gallery, you can easily create a backup of it by following these steps:
1. Note down the username and gallery id you want to back up. The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:
```sh
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

### Privy support

The server supports authenticating Privy JWT tokens using a TOML configuration file containing one or more credential sets, passed via the `--privy-config` flag.

Example `config_privy.toml` (multiple `[[privy]]` tables):

```toml
[[privy]]
app_id = "app_xxxxx"
verification_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"

[[privy]]
app_id = "app_yyyyy"
verification_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
```

All credential sets in the file are considered valid and tried during authentication.

### IPFS Pinning

There is support for pinning IPFS content using multiple providers. Both the [IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/) and the [Pinata API](https://docs.pinata.cloud/api-reference/introduction) are currently supported. 

Both the server and CLI can be configured to pin CIDs on IPFS via a TOML file passed with the `--ipfs-config` flag. Example `config_ipfs.toml`:

```toml
# Pin to a standard IPFS Pinning Service
[[ipfs_provider]]
type = "pinning-service"
base_url = "https://my-ipfs-service.example.com"
bearer_token_env = "IPFS_PINNING_SERVICE_TOKEN"

# Pin to Pinata
[[ipfs_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
bearer_token_env = "PINATA_TOKEN"
```

**Security best practice**: Use `bearer_token_env` to reference environment variables for API keys rather than embedding tokens directly in the config file. If both `bearer_token` and `bearer_token_env` are provided, `bearer_token_env` takes precedence.

## Run

### CLI

To run the CLI:

```sh
make run-cli
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

The server includes interactive OpenAPI documentation available at `/swagger-ui` when running. This provides a complete API reference with example requests and responses for all endpoints. The OpenAPI specification JSON is available at `/api-docs/openapi.json`.

Example usage:
```sh
# Start the server
make run-server

# View the interactive API documentation
open http://localhost:8080/swagger-ui
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
