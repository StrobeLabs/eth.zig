const std = @import("std");

// Keccak-256 parameters (Ethereum variant with 0x01 padding, NOT SHA3's 0x06)
const rate = 1088;
const capacity = 512;
const hash_bit_len = 256;
const delimited_suffix = 0x01;

/// 32-byte hash output type.
pub const Hash = [32]u8;

// XKCP C ABI types
const BitSequence = u8;
const BitLength = usize;
const HashReturn = enum(c_int) { success = 0, fail = 1, bad_hashlen = 2 };

const KeccakP1600_state = extern struct {
    data: [200]u8 align(64),
};

const SpongeInstance = extern struct {
    state: KeccakP1600_state,
    rate: c_uint,
    byteIOIndex: c_uint,
    squeezing: c_int,
};

const HashInstance = extern struct {
    sponge: SpongeInstance,
    fixedOutputLength: c_uint,
    delimitedSuffix: u8,
};

extern fn Keccak_HashInitialize(instance: *HashInstance, r: c_uint, c: c_uint, hashbitlen: c_uint, suffix: u8) HashReturn;
extern fn Keccak_HashUpdate(instance: *HashInstance, data: [*]const BitSequence, databitlen: BitLength) HashReturn;
extern fn Keccak_HashFinal(instance: *HashInstance, hashval: [*]BitSequence) HashReturn;
extern fn KeccakWidth1600_Sponge(r: c_uint, c: c_uint, input: [*]const u8, inputByteLen: usize, suffix: u8, output: [*]u8, outputByteLen: usize) c_int;

/// Compute the Keccak-256 hash of the given data (one-shot).
pub fn hash(data: []const u8) Hash {
    var result: Hash = undefined;
    const ret = KeccakWidth1600_Sponge(rate, capacity, data.ptr, data.len, delimited_suffix, &result, 32);
    std.debug.assert(ret == 0);
    return result;
}

/// Hasher for incremental hashing (used by hashConcat).
pub const Hasher = struct {
    instance: HashInstance,

    pub fn init() Hasher {
        var self: Hasher = undefined;
        const ret = Keccak_HashInitialize(&self.instance, rate, capacity, hash_bit_len, delimited_suffix);
        std.debug.assert(ret == .success);
        return self;
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        const ret = Keccak_HashUpdate(&self.instance, data.ptr, data.len * 8);
        std.debug.assert(ret == .success);
    }

    pub fn final(self: *Hasher) Hash {
        var result: Hash = undefined;
        const ret = Keccak_HashFinal(&self.instance, &result);
        std.debug.assert(ret == .success);
        return result;
    }
};
