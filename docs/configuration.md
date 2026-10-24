# Configuration

[Back to README](../README.md)

The server and standalone CLI read `config.toml`. Start with
[example_config.toml](../example_config.toml), which includes chain RPC URLs
and optional JWT, x402, and IPFS pinning settings. Remove optional sections
you do not use, including any subtables.

Both binaries load environment variables from `.env`. Start with
[.env.example](../.env.example) and fill in the credentials you need.
RPC URLs can reference environment variables using `${VARIABLE_NAME}`.

## Chains and token selection

Chain keys use case-sensitive [CAIP-2 identifiers][caip2], for example
`"eip155:1"` or `"tezos:NetXdQprcVkpaWU"`. Quote TOML keys containing a colon.
Known 1.x configuration aliases are accepted and normalized when loading
configuration; the 2.0 HTTP API accepts only CAIP-2 identifiers.

```toml
[chains]
"eip155:1" = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
"tezos:NetXdQprcVkpaWU" = "https://mainnet.smartpy.io"
```

The CLI reads token selections from `config_tokens.toml` for both local
backups and server requests. See
[example_config_tokens.toml](../example_config_tokens.toml). Each chain maps
to a list of `contract_address:token_id` strings:

```toml
"eip155:1" = ["0x3D7E6A293C5ca4cD6721Df1A99683802331793C7:26"]
"tezos:NetXdQprcVkpaWU" = ["KT1DmEFfeqEC3nEx6bpWKqjNY8FF8RFrR3Gc:28"]
```

### Import a Gallery collection

If you have a [Gallery](https://gallery.so) account, you can generate a token
configuration with
[extract_gallery_tokens.py](../scripts/extract_gallery_tokens.py).
The script requires Python 3 and the `requests` package.

Find your username and gallery ID in the gallery URL. For example,
`https://gallery.so/michalis/galleries/2RgusW2IT1qkSPKE15S2xTnArN4` has username
`michalis` and gallery ID `2RgusW2IT1qkSPKE15S2xTnArN4`.

```sh
GALLERY_ID=2RgusW2IT1qkSPKE15S2xTnArN4 \
USERNAME=michalis \
    python3 scripts/extract_gallery_tokens.py > config_tokens.toml
```

The script emits legacy chain aliases. Known aliases are normalized when the
CLI loads the file; review the generated selection before running a backup.

## JWT authentication

The server supports multiple JWT credential sets in `[[jwt]]` sections.
All configured sets are considered valid and tried during authentication.

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

The server also accepts a static bearer token from `NFTBK_AUTH_TOKEN`.
Set the same variable for the CLI when connecting with that token. See the
[API guide](api-v2.md#identity-and-requests) for principal ownership rules.

## IPFS pinning

Content can be pinned through multiple providers. Both the
[IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/)
and the [Pinata API](https://docs.pinata.cloud/api-reference/introduction)
are supported.

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

Set the referenced token variables in your environment or `.env`. To enable
pinning in the CLI, pass `--pin-on-ipfs true` to `create` or `server create`.
API clients request an IPFS output as described in the
[API guide](api-v2.md#create-a-snapshot).

## x402 payments

The server can require [x402](https://x402.org) micropayments for backup
generation. Enable payments with an `[x402]` section:

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
network = "eip155:84532"             # Facilitator network id
```

When enabled, create a quote with `POST /v2/quotes`, wait until it is ready,
then pass its `id` as `quote_id` in `POST /v2/backups`. Use a stable
`Idempotency-Key` across the initial request and its x402 payment retry.

See the [API and migration guide](api-v2.md#quotes-and-payments) for quote
binding, settlement recovery, and payment retries.

[caip2]: https://standards.chainagnostic.org/CAIPs/caip-2
