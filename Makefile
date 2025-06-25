.PHONY: all
all: fmt clippy test

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: clippy
clippy:
	cargo clippy -- -D warnings

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

.PHONY: run-server
run-server:
	cargo run --bin nftbk-server -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-pruner
run-pruner:
	cargo run --bin nftbk-pruner -- $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run-supervisor
run-supervisor:
	cargo run --bin nftbk-supervisor -- $(filter-out $@,$(MAKECMDGOALS))

