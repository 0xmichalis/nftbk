.PHONY: all
all: fmt clippy sort sqlxprepare test

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: clippy
clippy:
	cargo clippy -- -D warnings

.PHONY: sort
sort:
	@if ! command -v cargo-sort >/dev/null 2>&1; then \
		echo "cargo-sort not found! Install with: cargo install cargo-sort"; \
		exit 1; \
	fi
	cargo sort

.PHONY: sqlxprepare
sqlxprepare:
	@if ! command -v cargo sqlx >/dev/null 2>&1; then \
		echo "cargo sqlx not found! Install with: cargo install sqlx-cli"; \
		exit 1; \
	fi
	cargo sqlx prepare

.PHONY: test
test:
	cargo test

.PHONY: check
check:
	cargo check -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: build
build:
	cargo build -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-cli
run-cli:
	cargo run --bin nftbk-cli -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-cli-test
run-cli-test:
	cargo run --bin nftbk-cli -- --tokens-config-path config_tokens_test.toml --output-path nft_backup_test $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-server
run-server:
	cargo run --bin nftbk-server -- --unsafe-skip-checksum-check true --backup-parallelism 2 $(filter-out $@,$(MAKECMDGOALS))

.PHONY: start-db
start-db:
	scripts/start-postgres.sh

.PHONY: stop-db
stop-db:
	scripts/stop-postgres.sh

.PHONY: nuke-db
nuke-db:
	scripts/stop-postgres.sh
	podman volume rm nftbk_pgdata

.PHONY: migrate-db
migrate-db:
	sqlx migrate run
