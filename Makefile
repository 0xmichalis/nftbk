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
	cargo check

.PHONY: run
run:
	cargo run
