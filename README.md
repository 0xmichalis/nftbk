# nftbk

A library, server, and CLI tool for backing up NFT metadata and content from EVM and Tezos NFT contracts.

## Requirements

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs
- PostgreSQL (server-specific; used for backup metadata storage)

## Configuration

Two configuration files are used:
- `config_chains.toml`: Contains RPC URLs for different chains
- `config_tokens.toml`: Contains the NFT tokens to back up

Currently `config_chains.toml` includes a few prepopulated RPCs. Alchemy RPCs are used for EVM chains with an API key that can be configured as `EVM_RPC_API_KEY` inside an `.env` file. You can also choose to use different RPCs altogether. For `config_tokens.toml`, there is an `example_config_tokens.toml` that you can update as needed with the tokens to backup.

### Generate config from gallery.so

If you already have a [Gallery](https://gallery.so) account and gallery, you can easily create a backup of it by following these steps:
1. Note down the username and gallery id you want to back up. The gallery id is the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`  from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:
```bash
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

### Privy support

The server supports authenticating Privy JWT tokens, if both a `PRIVY_APP_ID` and a `PRIVY_VERIFICATION_KEY` are provided in its environment. For the key, set `\n` as newlines so the  key can be set within a single line to work around a limitation in multine support that the latest released `dotenv` version has.

## Run

To run the CLI:

```
cargo run --bin nftbk-cli -- [args]
```

To run the server:

```
cargo run --bin nftbk-server -- [args]
```

### Postgres

Deploy Postgres and run migrations:

```sh
cp .env.postgres.example .env.postgres
# fill out .env.postgres
make start-db
export DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}
sqlx migrate run
# to update the sqlx cache if needed
cargo sqlx prepare
```

## Contribute

Install the pre-commit hook to aid with development:

```
cp .hooks/pre-commit .git/hooks/pre-commit
```
