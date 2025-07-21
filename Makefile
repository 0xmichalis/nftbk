.PHONY: all
all: fmt clippy sort test

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: clippy
clippy:
	cargo clippy -- -D warnings

.PHONY: sort
sort:
	if ! command -v cargo-sort >/dev/null 2>&1; then \
		echo "cargo-sort not found! Install with: cargo install cargo-sort"; \
		exit 1; \
	fi
	cargo sort

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
