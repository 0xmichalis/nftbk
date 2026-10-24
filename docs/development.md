# Development

[Back to README](../README.md)

## Checks

Run the full local checks before submitting a change:

```sh
make all
```

This runs Rust formatting, dependency sorting, Clippy with warnings treated
as errors, and tests. The pre-commit hook runs the same checks and re-stages
files it reformats.

Cargo builds need `SQLX_OFFLINE=true` to use the checked-in SQLx query cache.
The `make build`, `make check`, `make clippy`, and `make test` targets set it
for you. Set it explicitly when invoking Cargo directly.

Lint Markdown files with:

```sh
npx markdownlint-cli2 README.md 'docs/**/*.md'
```

## SQLx query cache

After adding or updating a static SQLx query, start PostgreSQL with
`make start-db`, set `DATABASE_URL` in `.env`, and refresh the cache:

```sh
make sqlxprepare
```

Commit any resulting `.sqlx/` changes alongside the query changes. CI checks
that the cache matches the queries.

## Coverage

Generate and open an HTML coverage report:

```sh
make cover
```

The report is written to `target/coverage/tarpaulin-report.html`.
