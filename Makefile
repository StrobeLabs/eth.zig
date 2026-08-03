ZIG ?= zig
KCOV ?= kcov

.PHONY: build test fmt fmt-fix lint ci integration-test bench bench-u256 bench-keccak coverage docs clean

## Build the library (default)
build:
	$(ZIG) build

## Run unit tests (no network required)
test:
	$(ZIG) build test
	$(ZIG) build vector-test

## Check formatting — mirrors the CI fmt job
fmt:
	$(ZIG) fmt --check src/ tests/

## Auto-fix formatting
fmt-fix:
	$(ZIG) fmt src/ tests/

## Measure unit-test code coverage with kcov (Linux; requires kcov installed).
## Excludes vendored C/crypto so the report reflects the Zig SDK surface.
coverage:
	$(ZIG) build install-test
	rm -rf kcov-out
	$(KCOV) --include-pattern=src/ --exclude-pattern=src/crypto/ kcov-out ./zig-out/bin/test
	@echo "Coverage report: kcov-out/index.html"

## Generate API documentation into zig-out/docs
docs:
	$(ZIG) build docs

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
