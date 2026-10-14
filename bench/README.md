# Benchmarks

eth.zig benchmarks itself, release over release. The suite is ten operations
that dominate the hot loop of a trading bot, liquidator or searcher; anything
not on that list is either covered by one of them or too small to measure
reliably.

| Benchmark | What it measures |
|---|---|
| `keccak256_32b` | selector, storage-slot and mapping-key hashing |
| `keccak256_1kb` | calldata- and transaction-sized hashing |
| `secp256k1_sign` | signing a transaction hash |
| `secp256k1_recover` | recovering a sender from a signature (recover only) |
| `tx_hash_eip1559` | RLP-encoding an EIP-1559 transaction and hashing it |
| `abi_encode_transfer` | encoding `transfer(address,uint256)` calldata |
| `abi_decode_dynamic` | decoding `(string,bytes)` return data |
| `u256_mulDiv` | full-precision `a*b/c` with a 512-bit intermediate |
| `u256_uniswapv4_swap` | one exact-in swap-step price update |
| `dex_decode_universal_router` | decoding a real 4-command Universal Router `execute` |

## Running

```bash
zig build bench                                   # all ten
zig build bench -- --filter abi                   # a subset (substring match)
zig build bench -- --list                         # names and descriptions
zig build bench -- --json                         # machine-readable results
zig build bench -- --save results.json            # write results to a file
zig build bench -- --baseline results.json        # compare with a saved run
zig build bench -- --baseline results.json --fail-on-regression
```

The benchmark build is always `optimize=fast`, whatever `-Doptimize` says.

## How it measures

- Each benchmark is warmed up for 200 ms, then timed in batches sized to about
  10 ms so clock overhead is negligible.
- The figure is the **median ns/op over 31 batches** (`--samples`), reported to
  hundredths of a nanosecond, with the minimum and the median absolute
  deviation (as a percentage of the median) alongside.
- Inputs live in module-level variables and are read through an optimizer
  barrier on every call, so the compiler cannot constant-fold the work away.
  (The previous harness let several sub-10 ns benchmarks fold to a near no-op,
  and reported whole nanoseconds only.)
- On macOS the process asks for the user-interactive QoS class so it stays on
  performance cores.
- `--baseline` flags a regression only when the median is slower than the
  baseline by more than `--threshold` percent (default 5) **and** by more than
  twice the two runs' combined deviation.

## Comparing against a past version

A saved baseline is only meaningful on the same machine in the same state. The
reliable way to compare two versions is to build both and interleave their
runs with `bench/ab.py`:

```bash
# in a checkout of each ref (the harness exists from v0.10.1 on)
zig build bench-install --prefix /tmp/old    # -> /tmp/old/bin/bench
zig build bench-install --prefix /tmp/new

python3 bench/ab.py --rounds 7 /tmp/old/bin/bench /tmp/new/bin/bench
```

`ab.py` runs every binary once per round in a shuffled order and keeps each
benchmark's fastest per-run median. Interference (another process, a run moved
to efficiency cores) only ever makes a run slower, so the best round is the
closest estimate of what the code can do.

On a laptop doing other work, results are often bimodal: a run lands either
at full speed or roughly 1.7x slower. Use enough rounds that every binary gets
at least one fast round, and treat single-run absolute numbers with suspicion.
The nightly `Bench` workflow on a Linux runner uploads `bench-results.json`
for a longer-term trend.

## Latest results

Apple M4, macOS, 2026-10-10. `ab.py`, 7 interleaved rounds, fastest per-run
median. The baseline is v0.9.2 built with Zig 0.16.0 using this harness; the
candidate is this release built with Zig 0.17.0.

| Benchmark | v0.9.2 (Zig 0.16) | this release (Zig 0.17) | change |
|---|---:|---:|---:|
| `keccak256_32b` | 136.66 ns | 136.55 ns | -0.1% |
| `keccak256_1kb` | 1043.85 ns | 1047.39 ns | +0.3% |
| `secp256k1_sign` | 11421.14 ns | 11390.99 ns | -0.3% |
| `secp256k1_recover` | 15159.87 ns | 15158.16 ns | 0.0% |
| `tx_hash_eip1559` | 142.99 ns | 143.49 ns | +0.3% |
| `abi_encode_transfer` | 18.77 ns | 18.74 ns | -0.2% |
| `abi_decode_dynamic` | 15.77 ns | 16.95 ns | +7.5% |
| `u256_mulDiv` | 12.79 ns | 13.00 ns | +1.6% |
| `u256_uniswapv4_swap` | 24.09 ns | 21.94 ns | -8.9% |
| `dex_decode_universal_router` | (new in v0.10.0) | 154.04 ns | |

### Zig 0.17 notes

Zig 0.17 ships LLVM 22 with loop vectorization disabled to work around an LLVM
regression. Byte-at-a-time loops that 0.16 used to vectorize silently got
slower, which is what pushed `abi_decode_dynamic` 50% and Universal Router
decoding 2.3x slower right after the upgrade. The fixes read 8 bytes at a time
instead (offset/length words, zero-padding checks) and write RLP integers with
one big-endian store. The remaining `abi_decode_dynamic` gap is in code
generation for the decode loop itself, not in eth.zig's logic.
