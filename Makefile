.PHONY: all
all:
	cargo fmt --all
	cargo clippy -- -D warnings

.PHONY: test
test:
	cargo test

.PHONY: check
check:
	cargo check

.PHONY: run
run:
	cargo run
