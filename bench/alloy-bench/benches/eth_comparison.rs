use alloy_bench::*;
use alloy_primitives::{keccak256, Address, U256, Uint};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type U512 = Uint<512, 8>;

// ================================================================
// 1. Keccak256 benchmarks
// ================================================================

fn bench_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak256");

    group.bench_function("empty", |b| {
        b.iter(|| black_box(keccak256(black_box(b""))))
    });

    group.bench_function("32b", |b| {
        let data = TEST_MSG_HASH;
        b.iter(|| black_box(keccak256(black_box(&data))))
    });

    group.bench_function("256b", |b| {
        b.iter(|| black_box(keccak256(black_box(&KECCAK_256B))))
    });

    group.bench_function("1kb", |b| {
        b.iter(|| black_box(keccak256(black_box(&KECCAK_1KB))))
    });

    group.bench_function("4kb", |b| {
        b.iter(|| black_box(keccak256(black_box(&KECCAK_4KB))))
    });

    group.finish();
}

// ================================================================
// 2. secp256k1 ECDSA benchmarks
// ================================================================

fn bench_secp256k1(c: &mut Criterion) {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    let mut group = c.benchmark_group("secp256k1");

    group.bench_function("sign", |b| {
        let signing_key = SigningKey::from_bytes((&TEST_PRIVKEY).into()).unwrap();
        b.iter(|| {
            let (sig, _recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
                signing_key.sign_prehash(black_box(&TEST_MSG_HASH)).unwrap();
            black_box(sig);
        })
    });

    group.bench_function("sign_recover", |b| {
        use k256::ecdsa::VerifyingKey;
        let signing_key = SigningKey::from_bytes((&TEST_PRIVKEY).into()).unwrap();
        b.iter(|| {
            let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
                signing_key.sign_prehash(black_box(&TEST_MSG_HASH)).unwrap();
            let recovered =
                VerifyingKey::recover_from_prehash(&TEST_MSG_HASH, &sig, recid).unwrap();
            black_box(recovered);
        })
    });

    group.finish();
}

// ================================================================
// 3. Address benchmarks
// ================================================================

fn bench_address(c: &mut Criterion) {
    use k256::ecdsa::SigningKey;

    let mut group = c.benchmark_group("address");

    // Derive address from private key (pubkey -> keccak -> last 20 bytes)
    group.bench_function("derivation", |b| {
        let sk = SigningKey::from_bytes((&TEST_PRIVKEY).into()).unwrap();
        b.iter(|| {
            let vk = sk.verifying_key();
            let pubkey_bytes = vk.to_encoded_point(false);
            let hash = keccak256(&pubkey_bytes.as_bytes()[1..]);
            let addr = Address::from_slice(&hash[12..]);
            black_box(addr);
        })
    });

    // Parse address from hex string
    group.bench_function("from_hex", |b| {
        b.iter(|| {
            let addr: Address = black_box(ADDRESS_HEX).parse().unwrap();
            black_box(addr);
        })
    });

    // EIP-55 checksum formatting
    group.bench_function("checksum", |b| {
        b.iter(|| {
            let checksum = black_box(TEST_ADDR).to_checksum(None);
            black_box(checksum);
        })
    });

    group.finish();
}

// ================================================================
// 4. ABI encoding benchmarks
// ================================================================

fn bench_abi_encode(c: &mut Criterion) {
    use alloy_dyn_abi::DynSolValue;
    use alloy_sol_types::SolCall;

    let mut group = c.benchmark_group("abi_encode");

    // Static encoding: transfer(address, uint256) with selector
    group.bench_function("transfer_call", |b| {
        alloy_sol_types::sol! {
            function transfer(address to, uint256 amount) returns (bool);
        }
        b.iter(|| {
            let call = transferCall {
                to: black_box(TEST_ADDR),
                amount: black_box(ONE_ETH),
            };
            let encoded = call.abi_encode();
            black_box(encoded);
        })
    });

    // Static encoding without selector: (address, uint256)
    group.bench_function("static_addr_uint256", |b| {
        use alloy_dyn_abi::DynSolValue;
        b.iter(|| {
            let values = DynSolValue::Tuple(vec![
                DynSolValue::Address(black_box(TEST_ADDR)),
                DynSolValue::Uint(black_box(ONE_ETH), 256),
            ]);
            let encoded = values.abi_encode_params();
            black_box(encoded);
        })
    });

    // Dynamic encoding: (string, bytes, uint256[])
    group.bench_function("dynamic", |b| {
        b.iter(|| {
            let values = DynSolValue::Tuple(vec![
                DynSolValue::String(ABI_DYNAMIC_STRING.to_string()),
                DynSolValue::Bytes(ABI_DYNAMIC_BYTES.to_vec()),
                DynSolValue::Array(vec![
                    DynSolValue::Uint(U256::from(1), 256),
                    DynSolValue::Uint(U256::from(2), 256),
                    DynSolValue::Uint(U256::from(3), 256),
                    DynSolValue::Uint(U256::from(4), 256),
                    DynSolValue::Uint(U256::from(5), 256),
                ]),
            ]);
            let encoded = values.abi_encode_params();
            black_box(encoded);
        })
    });

    group.finish();
}

// ================================================================
// 5. ABI decoding benchmarks
// ================================================================

fn bench_abi_decode(c: &mut Criterion) {
    use alloy_dyn_abi::{DynSolType, DynSolValue};

    let mut group = c.benchmark_group("abi_decode");

    // Decode uint256
    group.bench_function("uint256", |b| {
        // Pre-encode: ABI encoding of uint256(1 ETH)
        let encoded = DynSolValue::Uint(ONE_ETH, 256).abi_encode_params();
        let ty = DynSolType::Uint(256);
        b.iter(|| {
            let decoded = ty.abi_decode(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });

    // Decode dynamic: (string, bytes)
    group.bench_function("dynamic", |b| {
        let encoded = DynSolValue::Tuple(vec![
            DynSolValue::String(ABI_DYNAMIC_STRING.to_string()),
            DynSolValue::Bytes(ABI_DYNAMIC_BYTES.to_vec()),
        ])
        .abi_encode_params();

        let ty = DynSolType::Tuple(vec![DynSolType::String, DynSolType::Bytes]);
        b.iter(|| {
            let decoded = ty.abi_decode_params(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });

    group.finish();
}

// ================================================================
// 6. RLP benchmarks
// ================================================================

fn bench_rlp(c: &mut Criterion) {
    use alloy_consensus::TxEip1559;
    use alloy_primitives::TxKind;
    use alloy_rlp::{Decodable, Encodable};

    let mut group = c.benchmark_group("rlp");

    // RLP encode EIP-1559 transaction
    group.bench_function("encode_eip1559_tx", |b| {
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(TEST_ADDR),
            value: ONE_ETH,
            input: Default::default(),
            access_list: Default::default(),
        };
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            black_box(&tx).encode(&mut buf);
            black_box(buf);
        })
    });

    // RLP decode u256
    group.bench_function("decode_u256", |b| {
        let mut encoded = Vec::new();
        ONE_ETH.encode(&mut encoded);
        b.iter(|| {
            let decoded = U256::decode(&mut black_box(encoded.as_slice())).unwrap();
            black_box(decoded);
        })
    });

    group.finish();
}

// ================================================================
// 7. U256 arithmetic benchmarks
// ================================================================

fn bench_u256(c: &mut Criterion) {
    let mut group = c.benchmark_group("u256");

    let a = ONE_ETH;
    let b_val = U256::from(997_000_000_000_000_000u64);

    group.bench_function("add", |b| {
        b.iter(|| {
            let result = black_box(a).checked_add(black_box(b_val));
            black_box(result);
        })
    });

    group.bench_function("mul", |b| {
        b.iter(|| {
            let result = black_box(a).checked_mul(U256::from(997u64));
            black_box(result);
        })
    });

    group.bench_function("div", |b| {
        let large = U256::from(997_000_000_000_000_000_000u128);
        b.iter(|| {
            let result = black_box(large).checked_div(black_box(a));
            black_box(result);
        })
    });

    // UniswapV2 getAmountOut full formula
    group.bench_function("uniswap_v2_amountOut", |b| {
        let amount_in = ONE_ETH;
        let reserve_in = U256::from(100_000_000_000_000_000_000u128);
        let reserve_out = U256::from(200_000_000_000u64);

        b.iter(|| {
            let amount_in_with_fee = black_box(amount_in) * U256::from(997);
            let numerator = amount_in_with_fee * black_box(reserve_out);
            let denominator = black_box(reserve_in) * U256::from(1000) + amount_in_with_fee;
            let amount_out = numerator / denominator;
            black_box(amount_out);
        })
    });

    // mulDiv: (a * b) / c with full 512-bit intermediate (FullMath.mulDiv)
    group.bench_function("mulDiv", |b| {
        let liquidity = ONE_ETH;
        let sqrt_price = U256::from_limbs([0, 79228162514264337593543950336u128 as u64, (79228162514264337593543950336u128 >> 64) as u64, 0]);
        let denom = ONE_ETH + U256::from(1_000_000u64);
        b.iter(|| {
            // True 512-bit intermediate: widen to U512, multiply, divide, narrow back
            let a = U512::from(black_box(liquidity));
            let b_val = U512::from(black_box(sqrt_price));
            let d = U512::from(black_box(denom));
            let result = U256::from((a * b_val) / d);
            black_box(result);
        })
    });

    // UniswapV4 getNextSqrtPriceFromAmount0RoundingUp (simplified non-overflow path).
    // Values are chosen so that product = amount_in * sqrt_price (~7.9e43) and
    // denominator = liquidity + product (~7.9e43) both fit in u256 without overflow,
    // so checked arithmetic is unnecessary here. The benchmark measures the hot path
    // that real swaps hit for typical pool parameters.
    group.bench_function("uniswap_v4_swap", |b| {
        let liquidity = ONE_ETH;
        let sqrt_price = U256::from_limbs([0, 79228162514264337593543950336u128 as u64, (79228162514264337593543950336u128 >> 64) as u64, 0]);
        let amount_in = U256::from(1_000_000_000_000_000u64);

        b.iter(|| {
            let product = black_box(amount_in) * black_box(sqrt_price);
            let denominator = black_box(liquidity) + product;
            // True 512-bit intermediate for numerator (liquidity * sqrt_price)
            let num = U512::from(black_box(liquidity)) * U512::from(black_box(sqrt_price));
            let next_sqrt_price = U256::from(num / U512::from(denominator));
            black_box(next_sqrt_price);
        })
    });

    group.finish();
}

// ================================================================
// 8. Hex encoding/decoding benchmarks
// ================================================================

fn bench_hex(c: &mut Criterion) {
    use alloy_primitives::hex;

    let mut group = c.benchmark_group("hex");

    group.bench_function("encode_32b", |b| {
        let data = TEST_MSG_HASH;
        b.iter(|| {
            let result = hex::encode(black_box(&data));
            black_box(result);
        })
    });

    group.bench_function("decode_32b", |b| {
        b.iter(|| {
            let result = hex::decode(black_box(HEX_STRING_32B)).unwrap();
            black_box(result);
        })
    });

    group.finish();
}

// ================================================================
// 9. Transaction hash benchmarks
// ================================================================

fn bench_tx_hash(c: &mut Criterion) {
    use alloy_consensus::TxEip1559;
    use alloy_primitives::TxKind;
    use alloy_rlp::Encodable;

    let mut group = c.benchmark_group("tx_hash");

    group.bench_function("eip1559", |b| {
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(TEST_ADDR),
            value: ONE_ETH,
            input: Default::default(),
            access_list: Default::default(),
        };
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            buf.push(0x02); // EIP-1559 type byte
            black_box(&tx).encode(&mut buf);
            let hash = keccak256(&buf);
            black_box(hash);
        })
    });

    group.finish();
}

// ================================================================
// Criterion groups and main
// ================================================================

criterion_group!(
    benches,
    bench_keccak,
    bench_secp256k1,
    bench_address,
    bench_abi_encode,
    bench_abi_decode,
    bench_rlp,
    bench_u256,
    bench_hex,
    bench_tx_hash,
);
criterion_main!(benches);
