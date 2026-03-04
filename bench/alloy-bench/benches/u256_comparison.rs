/// u256-only benchmark: eth.zig vs alloy.rs (ruint)
///
/// All test values match bench/u256_bench.zig exactly.
/// alloy's U256 is ruint::Uint<256, 4> -- native [u64; 4] limb arithmetic.

use alloy_primitives::{U256, Uint};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type U512 = Uint<512, 8>;

// ================================================================
// Test values -- identical to u256_bench.zig
// ================================================================

const ONE_ETH: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

// 100 ETH = 100_000_000_000_000_000_000 = 0x56BC75E2D63100000
const RESERVE_IN: U256 = U256::from_limbs([0x6BC75E2D63100000, 5, 0, 0]);
const RESERVE_OUT: U256 = U256::from_limbs([200_000_000_000u64, 0, 0, 0]);

// 2^96 = 79228162514264337593543950336
const SQRT_PRICE: U256 = U256::from_limbs([0, 0x100000000, 0, 0]);
const AMOUNT_IN_SMALL: U256 = U256::from_limbs([1_000_000_000_000_000u64, 0, 0, 0]);

// Full-width 256-bit values
const FULL_A: U256 = U256::from_limbs([
    0x12345678_9ABCDEF0,
    0xDEADBEEF_CAFEBABE,
    0x12345678_9ABCDEF0,
    0xDEADBEEF_CAFEBABE,
]);
const FULL_B: U256 = U256::from_limbs([
    0xDEADBEEF_CAFEBABE,
    0x12345678_9ABCDEF0,
    0xDEADBEEF_CAFEBABE,
    0x12345678_9ABCDEF0,
]);
const FULL_C: U256 = U256::from_limbs([
    0x00000000_00000001,
    0x00000000_00000000,
    0x00000000_00000000,
    0x00000001_00000000,
]);

// ================================================================
// Benchmarks
// ================================================================

fn bench_u256(c: &mut Criterion) {
    let mut group = c.benchmark_group("u256");

    // --- Primitives ---

    group.bench_function("add", |b| {
        let a = ONE_ETH;
        let b_val = U256::from(997_000_000_000_000_000u64);
        b.iter(|| {
            let result = black_box(a).wrapping_add(black_box(b_val));
            black_box(result);
        })
    });

    group.bench_function("mul_small", |b| {
        let a = ONE_ETH;
        b.iter(|| {
            let result = black_box(a).wrapping_mul(U256::from(997u64));
            black_box(result);
        })
    });

    group.bench_function("mul_full", |b| {
        b.iter(|| {
            let result = black_box(FULL_A).wrapping_mul(black_box(FULL_B));
            black_box(result);
        })
    });

    group.bench_function("div_small", |b| {
        let large = U256::from(997_000_000_000_000_000_000u128);
        b.iter(|| {
            let result = black_box(large) / black_box(ONE_ETH);
            black_box(result);
        })
    });

    group.bench_function("div_full", |b| {
        b.iter(|| {
            let result = black_box(FULL_A) / black_box(FULL_C);
            black_box(result);
        })
    });

    // --- UniswapV2 getAmountOut (naive: step-by-step u256 arithmetic) ---
    // Both Zig and Rust do the exact same formula with wrapping u256 ops.
    // This is the fair apples-to-apples comparison.

    group.bench_function("uniswapv2_naive", |b| {
        let amount_in = ONE_ETH;
        let reserve_in = RESERVE_IN;
        let reserve_out = RESERVE_OUT;
        b.iter(|| {
            let amount_in_with_fee = black_box(amount_in).wrapping_mul(U256::from(997u64));
            let numerator = amount_in_with_fee.wrapping_mul(black_box(reserve_out));
            let denominator =
                black_box(reserve_in).wrapping_mul(U256::from(1000u64)).wrapping_add(amount_in_with_fee);
            let amount_out = numerator / denominator;
            black_box(amount_out);
        })
    });

    // --- mulDiv: (a * b) / c with true 512-bit intermediate ---

    group.bench_function("mulDiv", |b| {
        let liquidity = ONE_ETH;
        let sqrt_price = SQRT_PRICE;
        let denom = ONE_ETH.wrapping_add(U256::from(1_000_000u64));
        b.iter(|| {
            let a = U512::from(black_box(liquidity));
            let b_val = U512::from(black_box(sqrt_price));
            let d = U512::from(black_box(denom));
            let result = U256::from((a * b_val) / d);
            black_box(result);
        })
    });

    // --- UniswapV4 getNextSqrtPriceFromAmount0RoundingUp ---
    // product = amount_in * sqrt_price (u256, no overflow for these values)
    // denominator = liquidity + product
    // next_sqrt_price = (liquidity * sqrt_price) / denominator  (via U512)

    group.bench_function("uniswapv4_swap", |b| {
        let liquidity = ONE_ETH;
        let sqrt_price = SQRT_PRICE;
        let amount_in = AMOUNT_IN_SMALL;
        b.iter(|| {
            let product = black_box(amount_in).wrapping_mul(black_box(sqrt_price));
            let denominator = black_box(liquidity).wrapping_add(product);
            let num = U512::from(black_box(liquidity)) * U512::from(black_box(sqrt_price));
            let next_sqrt_price = U256::from(num / U512::from(denominator));
            black_box(next_sqrt_price);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_u256);
criterion_main!(benches);
