ZIG ?= zig

.PHONY: build test fmt lint ci integration-test bench bench-u256 bench-keccak clean

## Build the library (default)
build:
	$(ZIG) build

## Run unit tests (no network required)
test:
	$(ZIG) build test

## Check formatting — mirrors the CI fmt job
fmt:
	$(ZIG) fmt --check src/ tests/

## Auto-fix formatting
fmt-fix:
	$(ZIG) fmt src/ tests/

## Run fmt + test — everything CI checks locally (no Anvil required)
lint: fmt test

## Full CI check: build + fmt + test (matches all CI jobs, still no Anvil)
ci: build fmt test

## Run integration tests (requires Anvil running on localhost:8545)
integration-test:
	$(ZIG) build integration-test

## Run all benchmarks (ReleaseFast)
bench:
	$(ZIG) build bench -Doptimize=ReleaseFast

bench-u256:
	$(ZIG) build bench-u256 -Doptimize=ReleaseFast

bench-keccak:
	$(ZIG) build bench-keccak -Doptimize=ReleaseFast

## Remove build artifacts
clean:
	rm -rf zig-out zig-cache .zig-cache
