CARGO ?= cargo

all: lint test

lint:
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) fmt --check

fix:
	$(CARGO) clippy --fix --allow-dirty --allow-staged
	$(CARGO) fmt

test:
	$(CARGO) test

.PHONY: all lint fix test
