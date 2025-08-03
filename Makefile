# Development-related targets

.PHONY: all
all: fmt sort clippy test

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: clippy
clippy:
	@SQLX_OFFLINE=true cargo clippy -- -D warnings

.PHONY: sort
sort:
	@if ! command -v cargo-sort >/dev/null 2>&1; then \
		cargo install cargo-sort; \
	fi
	cargo sort

.PHONY: sqlxprepare
sqlxprepare:
	@if ! command -v cargo sqlx >/dev/null 2>&1; then \
		cargo install sqlx-cli; \
	fi
	cargo sqlx prepare

.PHONY: test
test:
	@SQLX_OFFLINE=true cargo test

.PHONY: check
check:
	@SQLX_OFFLINE=true cargo check -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: build
build:
	@SQLX_OFFLINE=true cargo build -- $(filter-out $@,$(MAKECMDGOALS))


# Local run-related targets

.PHONY: run-cli
run-cli:
	@SQLX_OFFLINE=true cargo run --bin nftbk-cli -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-cli-test
run-cli-test:
	@SQLX_OFFLINE=true cargo run --bin nftbk-cli -- --tokens-config-path config_tokens_test.toml --output-path nft_backup_test $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-cli-server-test
run-cli-server-test:
	@SQLX_OFFLINE=true cargo run --bin nftbk-cli -- --tokens-config-path config_tokens_test.toml --output-path nft_backup_test --server-mode true $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run
run: start-db run-server

.PHONY: run-server
run-server:
	cargo run --bin nftbk-server -- --unsafe-skip-checksum-check true --backup-parallelism 2 $(filter-out $@,$(MAKECMDGOALS))

.PHONY: start-db
start-db:
	podman-compose up -d db

.PHONY: stop-db
stop-db:
	podman-compose down db

.PHONY: nuke-db
nuke-db: stop-db
	podman volume rm nftbk_pgdata

.PHONY: migrate-db
migrate-db:
	@if ! command -v cargo sqlx >/dev/null 2>&1; then \
		cargo install sqlx-cli; \
	fi
	sqlx migrate run

# Deployment-related targets

.PHONY: start-all
start-all:
	podman-compose -p nftbk-server up -d

.PHONY: stop-all
stop-all:
	podman-compose -p nftbk-server down

.PHONY: restart
restart:
	podman-compose -p nftbk-server down nftbk-server
	podman-compose -p nftbk-server up --pull nftbk-server -d
