# nftbk

[![CI][ci-badge]][ci] [![Coverage][coverage-badge]][coverage]

Back up NFT metadata and content from EVM networks (Ethereum, Base, Shape,
Zora, and others) and Tezos. Use nftbk as a Rust library, a standalone CLI,
or a server with an HTTP API. Backups can be saved locally or pinned to IPFS.

## Requirements

- Rust toolchain (install from [rustup.rs](https://rustup.rs)).
- An RPC URL for each network you want to back up.
- PostgreSQL for the server; the local database target also uses Podman and
  `podman-compose`.
- An IPFS pinning provider account if you want to pin content.

## Quick start

Run commands from the repository root. Copy the example configuration files:

```sh
cp .env.example .env
cp example_config.toml config.toml
cp example_config_tokens.toml config_tokens.toml
```

Edit the RPC URLs, credentials, and token selections for your collection.
Remove unused RPC entries and optional JWT, x402, and pinning sections until
you configure them. When removing `[x402]`, remove its subtables too.
See the [configuration guide](docs/configuration.md) for chain identifiers,
authentication, payments, pinning, and importing a Gallery collection.

### Create a local backup

```sh
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- create
```

This reads `config.toml` and `config_tokens.toml` and writes to `nft_backup/`.
PostgreSQL is only needed for server mode.

### Run the server

Set `DATABASE_URL` in `.env` to match your PostgreSQL credentials. To start
the bundled database and server:

```sh
cp .env.postgres.example .env.postgres
SQLX_OFFLINE=true make run
```

The server applies database migrations on startup and listens at
`http://127.0.0.1:8080`. Browse its interactive API reference at
[/v2/swagger-ui](http://127.0.0.1:8080/v2/swagger-ui); the OpenAPI JSON is at
[/v2/openapi.json](http://127.0.0.1:8080/v2/openapi.json).

See the [running guide](docs/running.md) for CLI options, an existing
database, manual migrations, and download behavior.

## Documentation

- [Configuration](docs/configuration.md): RPCs, token selection, Gallery
  import, JWT authentication, IPFS pinning, and x402 payments.
- [Running nftbk](docs/running.md): CLI and server usage, PostgreSQL,
  storage, and content download limits.
- [API and migration guide](docs/api-v2.md): resources, payment recovery,
  database model, and upgrading from 1.x.
- [Development](docs/development.md): checks, SQLx query cache, and coverage.

## Contribute

Run `make all` before submitting a change. See the
[development guide](docs/development.md) for the full workflow.

## Donations

To support development, you can donate to:

- Ethereum: `0xd2Be832911A252302bAc09e30Fc124A405E142DF` (michalis.eth)
- Tezos: `tz1ioFzpKGdwtncBkGunkUD9Sk16NqB2vML6` (michalis.tez)

[ci-badge]: https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml/badge.svg
[ci]: https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml
[coverage-badge]: https://coveralls.io/repos/github/0xmichalis/nftbk/badge.svg?branch=main
[coverage]: https://coveralls.io/github/0xmichalis/nftbk?branch=main
