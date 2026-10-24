# Running nftbk

[Back to README](../README.md)

Complete the [initial configuration](../README.md#quick-start) before
running the CLI or server. Run the commands below from the repository root.

## CLI

List the supported options:

```sh
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- --help
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- create --help
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- server --help
```

Create a local backup with an explicit output directory:

```sh
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- create \
    --tokens-config-path config_tokens.toml \
    --output-path nft_backup
```

To request a backup from a running server instead:

```sh
SQLX_OFFLINE=true cargo run --bin nftbk-cli -- server create \
    --server-address http://127.0.0.1:8080 \
    --tokens-config-path config_tokens.toml \
    --output-path nft_backup
```

The Makefile also provides `make run-cli-test` for local backups and
`make run-cli-server-test` for server requests. Both use
`config_tokens_test.toml` and write to `nft_backup_test/`.

## PostgreSQL and server startup

The server requires PostgreSQL for backup metadata and operation state. Set
`DATABASE_URL` in `.env` to match your database. To start the bundled
PostgreSQL instance with Podman:

```sh
cp .env.postgres.example .env.postgres
make start-db
```

The server applies pending migrations automatically on startup. If
PostgreSQL is already running, start just the server:

```sh
SQLX_OFFLINE=true make run-server
```

Alternatively, `SQLX_OFFLINE=true make run` starts both the database and
server. These Makefile targets use local development settings, including
`--unsafe-skip-checksum-check true`. To choose your own server options:

```sh
SQLX_OFFLINE=true cargo run --bin nftbk-server -- --help
SQLX_OFFLINE=true cargo run --bin nftbk-server -- --base-dir ./data
```

The binary defaults to `/tmp` for storage. Use a persistent base directory
for backups you intend to keep.

### Manual migrations

Migrations live in `migrations/` and are embedded in the server binary at
build time. To apply them without starting the server, install the SQLx CLI,
set `DATABASE_URL` in your shell, and run:

```sh
sqlx migrate run
```

### API reference

The running server exposes interactive OpenAPI documentation with example
requests and responses at
[/v2/swagger-ui](http://127.0.0.1:8080/v2/swagger-ui). The specification JSON
is at [/v2/openapi.json](http://127.0.0.1:8080/v2/openapi.json).

## Content downloads

NFT metadata, media, and extra resources must use public HTTP(S)
destinations, including every redirect and DNS result. Content fetches
ignore proxy environment variables; configured RPC, pinning, and payment
endpoints retain their existing network access.

HTTP(S) URLs are tried unchanged before falling back to IPFS gateways.
IPFS URIs use Filebase and Pinata, preferring authenticated gateways.
Artwork query parameters and fragments are preserved when switching
gateways.

Downloads allow 10 seconds to connect, 30 seconds per read, and 5 minutes
in total per request. Buffered metadata is limited to 16 MiB; saved media
is limited to 256 MiB per file, including decompressed content. These limits
allow large NFT media while bounding memory, disk use, and stalled requests.
Failed downloads remove partial files. Larger artwork needs another backup
method.

Backup error messages omit HTTP(S) and WebSocket endpoint URLs to keep RPC
credentials private while retaining the underlying capture failure details.
API responses also redact URLs in migrated error logs. Those stored rows
are not rewritten; remove credentials from them manually if needed.
