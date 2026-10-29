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

# Timings and exact allocation counts. Record a baseline before a change with
# `make bench-save`, then `make bench-check` fails on a regression against it.
BASELINE ?= main

bench:
	$(CARGO) bench --bench burton

bench-save:
	$(CARGO) bench --bench burton -- --save $(BASELINE)

bench-check:
	$(CARGO) bench --bench burton -- --baseline $(BASELINE)

.PHONY: all lint fix test msrv bench bench-save bench-check
