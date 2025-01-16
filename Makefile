.PHONY: all
all:
	cargo fmt --all
	cargo clippy -- -D warnings
