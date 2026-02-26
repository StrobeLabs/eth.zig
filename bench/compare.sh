#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ALLOY_DIR="$SCRIPT_DIR/alloy-bench"

echo ""
echo "================================================================"
echo "  eth-zig vs alloy.rs  --  Benchmark Comparison"
echo "================================================================"
echo ""

# -- Step 1: Run eth-zig benchmarks --
echo "[1/3] Running eth-zig benchmarks (ReleaseFast)..."
ZIG_OUTPUT=$(cd "$ROOT_DIR" && zig build bench 2>&1)
echo "$ZIG_OUTPUT" | grep -v "^BENCH_JSON"
echo ""

# -- Step 2: Run alloy.rs benchmarks --
echo "[2/3] Running alloy.rs benchmarks (cargo bench --release)..."
if [ ! -d "$ALLOY_DIR" ]; then
    echo "ERROR: $ALLOY_DIR not found."
    exit 1
fi
RUST_OUTPUT=$(cd "$ALLOY_DIR" && cargo bench --bench eth_comparison 2>&1)
echo "  Done."
echo ""

# -- Step 3: Parse and compare using Python --
echo "[3/3] Comparing results..."
echo ""

python3 - "$ZIG_OUTPUT" "$RUST_OUTPUT" << 'PYTHON_SCRIPT'
import sys
import json
import re

zig_output = sys.argv[1]
rust_output = sys.argv[2]

# Parse eth-zig BENCH_JSON lines
zig_ns = {}
for line in zig_output.split('\n'):
    if line.startswith('BENCH_JSON|'):
        data = json.loads(line[len('BENCH_JSON|'):])
        zig_ns[data['name']] = data['ns_per_op']

# Parse criterion output
alloy_ns = {}
current_bench = None
for line in rust_output.split('\n'):
    # Match "Benchmarking group/name" (without trailing text like ": Warming up")
    m = re.match(r'^Benchmarking ([a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\s*$', line.strip())
    if m:
        current_bench = m.group(1)
        continue
    # Match time line
    if current_bench:
        m = re.search(r'time:\s+\[[\d.]+ \w+\s+([\d.]+)\s+(ns|µs|ms)', line)
        if m:
            value = float(m.group(1))
            unit = m.group(2)
            if unit == 'ns':
                ns_val = round(value)
            elif unit == 'µs':
                ns_val = round(value * 1000)
            elif unit == 'ms':
                ns_val = round(value * 1000000)
            alloy_ns[current_bench] = ns_val
            current_bench = None

# Name mapping: eth-zig -> criterion
name_map = {
    'keccak256_empty': 'keccak256/empty',
    'keccak256_32b': 'keccak256/32b',
    'keccak256_256b': 'keccak256/256b',
    'keccak256_1kb': 'keccak256/1kb',
    'keccak256_4kb': 'keccak256/4kb',
    'secp256k1_sign': 'secp256k1/sign',
    'secp256k1_sign_recover': 'secp256k1/sign_recover',
    'address_derivation': 'address/derivation',
    'address_from_hex': 'address/from_hex',
    'checksum_address': 'address/checksum',
    'abi_encode_transfer': 'abi_encode/transfer_call',
    'abi_encode_static': 'abi_encode/static_addr_uint256',
    'abi_encode_dynamic': 'abi_encode/dynamic',
    'abi_decode_uint256': 'abi_decode/uint256',
    'abi_decode_dynamic': 'abi_decode/dynamic',
    'rlp_encode_eip1559_tx': 'rlp/encode_eip1559_tx',
    'rlp_decode_u256': 'rlp/decode_u256',
    'u256_add': 'u256/add',
    'u256_mul': 'u256/mul',
    'u256_div': 'u256/div',
    'u256_uniswapv2_amount_out': 'u256/uniswap_v2_amountOut',
    'hex_encode_32b': 'hex/encode_32b',
    'hex_decode_32b': 'hex/decode_32b',
    'tx_hash_eip1559': 'tx_hash/eip1559',
}

bench_order = [
    'keccak256_empty', 'keccak256_32b', 'keccak256_256b', 'keccak256_1kb', 'keccak256_4kb',
    'secp256k1_sign', 'secp256k1_sign_recover',
    'address_derivation', 'address_from_hex', 'checksum_address',
    'abi_encode_transfer', 'abi_encode_static', 'abi_encode_dynamic',
    'abi_decode_uint256', 'abi_decode_dynamic',
    'rlp_encode_eip1559_tx', 'rlp_decode_u256',
    'u256_add', 'u256_mul', 'u256_div', 'u256_uniswapv2_amount_out',
    'hex_encode_32b', 'hex_decode_32b',
    'tx_hash_eip1559',
]

# Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
BOLD = '\033[1m'
NC = '\033[0m'

print(f"{BOLD}{'Benchmark':<34} {'eth-zig':>12} {'alloy.rs':>12} {'Result':>18}{NC}")
print(f"{'-'*34} {'-'*12} {'-'*12} {'-'*18}")

zig_wins = 0
alloy_wins = 0
total = 0

for zig_name in bench_order:
    alloy_name = name_map.get(zig_name, '')
    z = zig_ns.get(zig_name)
    a = alloy_ns.get(alloy_name)

    if z is not None and a is not None:
        total += 1
        if z == 0 and a == 0:
            label = 'equal'
            color = NC
        elif z < a:
            ratio = a / z if z > 0 else 999.99
            label = f'{ratio:.2f}x faster (zig)'
            color = GREEN
            zig_wins += 1
        elif a < z:
            ratio = z / a if a > 0 else 999.99
            label = f'{ratio:.2f}x faster (rs)'
            color = RED
            alloy_wins += 1
        else:
            label = 'equal'
            color = NC
        print(f"{zig_name:<34} {z:>9} ns {a:>9} ns {color}{label:>18}{NC}")
    elif z is not None:
        print(f"{zig_name:<34} {z:>9} ns {'---':>12} {'(zig only)':>18}")

print()
print(f"{'='*34} {'='*12} {'='*12} {'='*18}")
print()
print(f"Summary: eth-zig wins {zig_wins} / {total} | alloy.rs wins {alloy_wins} / {total}")
print()

# eth-zig only benchmarks
print("eth-zig only benchmarks (no alloy equivalent):")
for name in ['hd_wallet_derive_10', 'eip712_hash_typed_data']:
    z = zig_ns.get(name)
    if z is not None:
        print(f"  {name:<32} {z:>9} ns")
print()
PYTHON_SCRIPT
