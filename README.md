# nftbk

![x402 badge](assets/x402-button-small.png)

[![CI](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml/badge.svg)](https://github.com/0xmichalis/nftbk/actions/workflows/ci.yml)[![Coverage](https://coveralls.io/repos/github/0xmichalis/nftbk/badge.svg?branch=main)](https://coveralls.io/github/0xmichalis/nftbk?branch=main)

A library, server, and CLI tool for protecting NFTs. The following networks are
currently supported:

- EVM (Ethereum, Base, Shape, Zora, etc)
- Tezos

## Requirements

- Rust toolchain (install from [rustup.rs](https://rustup.rs))
- Chain-specific RPC URLs
- IPFS pinning service (optional)
- PostgreSQL (server-specific; used for backup metadata storage)

## Configuration

The server uses a configuration file that combines all settings.
See `example_config.toml` for an example config. It contains:

- Chain RPC URLs
- JWT authentication credentials (optional)
- x402 payment configuration (optional)
- IPFS pinning providers (optional)

The CLI uses additionally a config file for the tokens to be backed up when
running in standalone mode. See `example_config_tokens.toml` for an example.

### Generate config from gallery.so

If you already have a [Gallery](https://gallery.so) account and gallery, you can
easily create a backup of it by following these steps:

1. Note down the username and gallery id you want to back up. The gallery id is
the last part of the URL when viewing a gallery, eg, `2RgusW2IT1qkSPKE15S2xTnArN4`
from [`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4`](https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4).
2. Run the following command to generate a config file:

```sh
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

### JWT authentication support

The server supports authenticating JWT tokens. Multiple JWT credential sets can
be configured in the `[[jwt]]` section of the server config. All credential sets
in the config are considered valid and tried during authentication.

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

### IPFS Pinning

There is support for pinning IPFS content using multiple providers. Both the
[IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/)
and the [Pinata API](https://docs.pinata.cloud/api-reference/introduction)
are currently supported.

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

### x402 payments

The server can lock backup generation behind [x402](https://x402.org)
micropayments. Enable it by adding an `[x402]` stanza to your config:

```toml
[x402]
asset_symbol = "USDC"                # Settlement asset (USDC supported today)
base_url = "https://localhost:8080"  # Public base URL echoed in 402 replies
recipient_address = "0x..."          # Wallet that receives payments
max_timeout_seconds = 300            # How long a quote remains payable

[x402.pricing]
archive_price_per_gb = "0.05"        # USDC per GB for archive downloads
pin_price_per_gb = "0.2"             # USDC per GB for IPFS pinning

[x402.facilitator]
url = "https://x402.org/facilitator" # Facilitator endpoint
network = "base-sepolia"             # Facilitator network id
```

When enabled, callers should first request quotes via `POST /v1/backups/quote`;
the quote should subsequently be used as part of the normal `POST /v1/backups`
request.

## Run

### CLI

Check the supported options in the CLI:

```sh
cargo run --bin nftbk-cli -- --help
```

A few useful targets in the Makefile:

```sh
# Create a local backup based on config.toml and config_tokens.toml
make run-cli
# Request a backup from a local server running at localhost:8080 using
# tokens defined in config_tokens_test.toml
make run-cli-server-test 
```

### Postgres

Postgres is a requirement in order to run the server. Deploy Postgres and
run migrations by following these instructions:

```sh
# Run database
cp .env.postgres.example .env.postgres
make start-db

# Run migrations
export DATABASE_URL=postgres://nftbkuser:nftbkpassword@localhost:5432/nftbkdb
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

### Cloudflare + Caddy (TLS via DNS-01)

If you deploy behind Cloudflare and want to keep the proxy enabled (orange
cloud) while using automatic TLS via Let's Encrypt, switch Caddy to use the
Cloudflare DNS-01 challenge:

1. Create a Cloudflare API Token with permissions: `Zone.Zone: Read` and
   `Zone.DNS: Edit`, restricted to your domain zone.
2. Set the token as `CLOUDFLARE_API_TOKEN` in `.env.caddy`.
3. In Cloudflare SSL/TLS settings, set mode to "Full (strict)".
4. Restart Caddy

### OpenAPI Documentation

The server includes interactive OpenAPI documentation available at `/v1/swagger-ui`
when running. This provides a complete API reference with example requests and
responses for all endpoints. The OpenAPI specification JSON is available at
`/v1/api-docs/openapi.json`.

Example usage:

```sh
# Start the server
make run-server

# View the interactive API documentation
open http://localhost:8080/v1/swagger-ui
```

## Contribute

```sh
# Update the sqlx cache and commit any changes when necessary - this is needed
# when developing new or updating existing static queries in the server.
make sqlxprepare

# Run tests with coverage output in HTML
make cover
```

## Donations

If you find this project helpful and would like to support its development, you
can make a donation in the following addresses:

- Ethereum: `0xd2Be832911A252302bAc09e30Fc124A405E142DF` (michalis.eth)
- Tezos: `tz1ioFzpKGdwtncBkGunkUD9Sk16NqB2vML6` (michalis.tez)
