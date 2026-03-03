#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ALLOY_DIR="$SCRIPT_DIR/alloy-bench"

command -v zig >/dev/null 2>&1 || { echo "ERROR: zig not found"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }

echo ""
echo "================================================================"
echo "  u256 Benchmark: eth.zig vs alloy.rs (ruint)"
echo "================================================================"
echo ""

# -- Step 1: eth-zig u256 benchmarks --
echo "[1/3] Running eth-zig u256 benchmarks (ReleaseFast)..."
ZIG_OUTPUT=$(cd "$ROOT_DIR" && zig build bench-u256 2>&1)
echo "$ZIG_OUTPUT" | grep -v "^BENCH_JSON"
echo ""

# -- Step 2: alloy.rs u256 benchmarks --
echo "[2/3] Running alloy.rs u256 benchmarks (cargo bench --release)..."
RUST_OUTPUT=$(cd "$ALLOY_DIR" && cargo bench --bench u256_comparison 2>&1)
echo "  Done."
echo ""

# -- Step 3: Compare --
echo "[3/3] Comparing results..."
echo ""

python3 - "$ZIG_OUTPUT" "$RUST_OUTPUT" << 'PYTHON_SCRIPT'
import sys
import json
import re

zig_output = sys.argv[1]
rust_output = sys.argv[2]

def parse_ns(value_str, unit_str):
    v = float(value_str)
    if unit_str == 'ns':
        return round(v)
    elif unit_str in ('us', 'µs'):
        return round(v * 1000)
    elif unit_str == 'ms':
        return round(v * 1_000_000)
    return round(v)

# Parse BENCH_JSON lines from Zig output
zig_ns = {}
for line in zig_output.split('\n'):
    if line.startswith('BENCH_JSON|'):
        try:
            data = json.loads(line[len('BENCH_JSON|'):])
            zig_ns[data['name']] = data['ns_per_op']
        except (json.JSONDecodeError, KeyError):
            pass

# Parse criterion output
alloy_ns = {}
for line in rust_output.split('\n'):
    m = re.match(r'^([a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\s+time:\s+\[[\d.]+ \w+\s+([\d.]+)\s+(ns|µs|ms)', line.strip())
    if m:
        alloy_ns[m.group(1)] = parse_ns(m.group(2), m.group(3))

# Name mapping: zig -> criterion
name_map = {
    'u256_add':                   'u256/add',
    'u256_mul_small':             'u256/mul_small',
    'u256_mul_full':              'u256/mul_full',
    'u256_div_small':             'u256/div_small',
    'u256_div_full':              'u256/div_full',
    'u256_uniswapv2_naive':       'u256/uniswapv2_naive',
    'u256_mulDiv':                'u256/mulDiv',
    'u256_uniswapv4_swap':        'u256/uniswapv4_swap',
}

bench_order = [
    'u256_add',
    'u256_mul_small',
    'u256_mul_full',
    'u256_div_small',
    'u256_div_full',
    'u256_uniswapv2_naive',
    'u256_mulDiv',
    'u256_uniswapv4_swap',
]

GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[0;33m'
BOLD = '\033[1m'
NC = '\033[0m'

print(f"\n{BOLD}=== Apples-to-apples: same formula, same u256 ops ==={NC}\n")
print(f"{BOLD}{'Benchmark':<28} {'eth-zig':>10} {'alloy.rs':>10} {'Result':>20}{NC}")
print(f"{'-'*28} {'-'*10} {'-'*10} {'-'*20}")

zig_wins = 0
alloy_wins = 0
ties = 0
total = 0

for zig_name in bench_order:
    alloy_name = name_map.get(zig_name, '')
    z = zig_ns.get(zig_name)
    a = alloy_ns.get(alloy_name)

    if z is not None and a is not None:
        total += 1
        if z == a or (z > 0 and a > 0 and abs(z - a) / max(z, a) < 0.1):
            label = 'tie'
            color = NC
            ties += 1
        elif z < a:
            ratio = a / z if z > 0 else 999.99
            label = f'zig {ratio:.2f}x'
            color = GREEN
            zig_wins += 1
        else:
            ratio = z / a if a > 0 else 999.99
            label = f'rs {ratio:.2f}x'
            color = RED
            alloy_wins += 1
        print(f"{zig_name:<28} {z:>7} ns {a:>7} ns {color}{label:>20}{NC}")
    elif z is not None:
        print(f"{zig_name:<28} {z:>7} ns {'---':>10} {'(zig only)':>20}")

print(f"\n{BOLD}{'='*28} {'='*10} {'='*10} {'='*20}{NC}")
print(f"\n{BOLD}Score: eth-zig {zig_wins}/{total} | alloy.rs {alloy_wins}/{total} | tied {ties}/{total}{NC}")

# Show zig-only optimized benchmark
z_opt = zig_ns.get('u256_uniswapv2_optimized')
z_naive = zig_ns.get('u256_uniswapv2_naive')
a_naive = alloy_ns.get('u256/uniswapv2_naive')

if z_opt is not None:
    print(f"\n{BOLD}=== eth.zig compound limb optimization ==={NC}\n")
    print(f"{'u256_uniswapv2_optimized':<28} {z_opt:>7} ns   (stays in [4]u64 limb space)")
    if z_naive is not None and z_naive > 0:
        print(f"{'u256_uniswapv2_naive':<28} {z_naive:>7} ns   (step-by-step u256, same as alloy)")
        speedup = z_naive / z_opt if z_opt > 0 else 0
        print(f"{'Optimization speedup':<28} {YELLOW}{speedup:.2f}x{NC}")
    if a_naive is not None and z_opt > 0:
        vs_rust = a_naive / z_opt
        if vs_rust >= 1:
            print(f"{'vs alloy.rs naive':<28} {GREEN}{vs_rust:.2f}x faster{NC}")
        else:
            print(f"{'vs alloy.rs naive':<28} {RED}{1/vs_rust:.2f}x slower{NC}")

print()
PYTHON_SCRIPT
