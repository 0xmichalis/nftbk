# nftbk

[![CI](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml/badge.svg)](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml)

A library, server, and CLI tool for backing up NFT metadata and content from EVM and Tezos NFT contracts.

## Requirements

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs
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

The server supports authenticating Privy JWT tokens, if both a `PRIVY_APP_ID` and a `PRIVY_VERIFICATION_KEY` are provided in its environment. For the key, set `\n` as newlines so the  key can be set within a single line to work around a limitation in multine support that the latest released `dotenv` version has.

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
cp .hooks/pre-commit .git/hooks/pre-commit

# Update the sqlx cache and commit any changes when necessary - this is needed when developing new
# queries or updating existing queries in the server.
make sqlxprepare
```
