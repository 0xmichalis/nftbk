# Development-related targets

.PHONY: all
all: fmt sort clippy test

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: clippy
clippy:
	@SQLX_OFFLINE=true cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: sort
sort:
	@if ! cargo-sort --version >/dev/null 2>&1; then \
		cargo install cargo-sort; \
	fi
	cargo sort

.PHONY: sqlxprepare
sqlxprepare:
	@if ! cargo sqlx --version >/dev/null 2>&1; then \
		cargo install sqlx-cli; \
	fi
	cargo sqlx prepare

.PHONY: cover
cover:
	@if ! cargo tarpaulin --version >/dev/null 2>&1; then \
		cargo install cargo-tarpaulin; \
	fi
	@SQLX_OFFLINE=true cargo tarpaulin \
		--workspace \
		--all-features \
		--ignore-tests \
		--engine llvm \
		--timeout 120 \
		--skip-clean \
		--out Html \
		--output-dir target/coverage
	@open target/coverage/tarpaulin-report.html

.PHONY: cover-lcov
cover-lcov:
	@if ! cargo tarpaulin --version >/dev/null 2>&1; then \
		cargo install cargo-tarpaulin; \
	fi
	@SQLX_OFFLINE=true cargo tarpaulin \
		--workspace \
		--all-features \
		--ignore-tests \
		--engine llvm \
		--skip-clean \
		--timeout 120 \
		--out Lcov \
		--output-dir .

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
run: start-db migrate-db run-server

.PHONY: run-server
run-server:
	@if [ -f config_privy.toml ]; then PRIVY_ARG="--privy-config config_privy.toml"; else PRIVY_ARG=""; fi; \
	    if [ -f config_ipfs.toml ]; then IPFS_ARG="--ipfs-config config_ipfs.toml"; else IPFS_ARG=""; fi; \
		cargo run --bin nftbk-server -- --unsafe-skip-checksum-check true --backup-parallelism 2 $$PRIVY_ARG $$IPFS_ARG

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
	@if ! cargo sqlx --version >/dev/null 2>&1; then \
		cargo install sqlx-cli; \
	fi
	@echo "Attempting to run database migrations (with retry on startup errors)..."
	@max_attempts=5; \
	attempt=1; \
	while [ $$attempt -le $$max_attempts ]; do \
		echo "Migration attempt $$attempt/$$max_attempts..."; \
		if sqlx migrate run; then \
			echo "Database migration successful!"; \
			break; \
		else \
			if [ $$attempt -eq $$max_attempts ]; then \
				echo "Migration failed after $$max_attempts attempts"; \
				exit 1; \
			fi; \
			echo "Migration failed, waiting 2 seconds before retry..."; \
			sleep 2; \
			attempt=$$((attempt + 1)); \
		fi; \
	done

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
