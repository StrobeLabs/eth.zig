use std::env;
use std::hint::black_box;

fn main() {
    let args: Vec<String> = env::args().collect();
    let size: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(32);
    let iters: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(1_000_000);
    let backend = args.get(3).map(|s| s.as_str()).unwrap_or("asm");

    let data: Vec<u8> = vec![0xAB; size];

    match backend {
        "asm" => {
            for _ in 0..iters {
                let result = keccak_asm::Keccak256::digest(black_box(&data));
                black_box(&result);
            }
        }
        "tiny" => {
            use tiny_keccak::{Hasher, Keccak};
            for _ in 0..iters {
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(black_box(&data));
                hasher.finalize(&mut output);
                black_box(&output);
            }
        }
        _ => panic!("Unknown backend: {}", backend),
    }
}
