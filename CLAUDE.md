# nftbk

Rust library, server (`nftbk-server`: axum + sqlx/PostgreSQL) and CLI
(`nftbk-cli`) that back up NFT metadata and content from EVM and Tezos
contracts. Single crate: `src/lib.rs` plus binaries in `src/bin/`.

## Commands

`make all` runs fmt, cargo-sort, clippy with `-D warnings`, and tests. Run
it before calling a change done. The pre-commit hook runs it too and
re-stages whatever it reformats.

Cargo needs `SQLX_OFFLINE=true`; the Makefile targets (`make test`,
`make check`, `make build`, `make clippy`) set it. Seeing
`error communicating with database` means cargo ran without it.

After changing a `sqlx::query!` call, refresh `.sqlx/` with
`make sqlxprepare` (needs `make start-db` and `DATABASE_URL` from `.env`).
CI fails on a stale cache.

## Testing

* Unit tests live in the module they cover, one module per function,
  named `mod <function_name>_tests`.
* No real or dummy database in unit tests. Database access goes through the
  `Database` trait in `src/server/database/trait.rs`; tests mock it.
* Mock blockchain RPCs, IPFS gateways and every other external HTTP call
  with `wiremock`.

## Dependencies

CI runs `cargo audit`, `cargo deny check bans licenses sources` and
`cargo vet --locked`. A new or bumped crate needs an audit or exemption
under `supply-chain/`. RUSTSEC ignores live in `.cargo/audit.toml`, each
with a comment saying why it is ignored.

## Markdown

CI lints with `markdownlint-cli2` on default rules, so wrap prose at 80
columns. Check locally with `npx markdownlint-cli2 <file>`.

## Secrets

`.env`, `config.toml` and `config_*.toml` are gitignored and hold real
credentials. Never commit them and never echo their values into logs or
output. Start from the `.example` files.

## Working agreement

* Change only what was asked. No drive-by refactors, renames or cleanup of
  adjacent code.
* Keep existing comments unless your change made them wrong. Don't leave a
  comment where you deleted code.
* Rate your confidence in a proposed solution 1-10.

Rust conventions load from `.claude/rules/rust.md` when you touch a `.rs`
file.
