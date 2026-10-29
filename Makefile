CARGO ?= cargo
MSRV ?= 1.88.0

all: lint test

lint:
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) fmt --check
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps

fix:
	$(CARGO) clippy --fix --allow-dirty --allow-staged
	$(CARGO) fmt

test:
	$(CARGO) test

msrv:
	rustup run $(MSRV) $(CARGO) test

.PHONY: all lint fix test msrv
