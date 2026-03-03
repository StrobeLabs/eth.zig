use std::slice;

/// keccak-asm (assembly-optimized, what Voltaire uses natively)
#[no_mangle]
pub unsafe extern "C" fn rust_keccak_asm(input: *const u8, input_len: usize, output: *mut u8) {
    let data = unsafe { slice::from_raw_parts(input, input_len) };
    let hash = keccak_asm::Keccak256::digest(data);
    let out = unsafe { slice::from_raw_parts_mut(output, 32) };
    out.copy_from_slice(&hash);
}

/// tiny-keccak (pure Rust, what Voltaire uses for WASM)
#[no_mangle]
pub unsafe extern "C" fn rust_tiny_keccak(input: *const u8, input_len: usize, output: *mut u8) {
    use tiny_keccak::{Hasher, Keccak};
    let data = unsafe { slice::from_raw_parts(input, input_len) };
    let out = unsafe { slice::from_raw_parts_mut(output, 32) };
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(out);
}
