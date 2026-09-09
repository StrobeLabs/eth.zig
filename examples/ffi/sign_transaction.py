"""Sign an EIP-1559 transaction offline with ctypes. No pip dependencies.

Run after `zig build c-lib -Doptimize=ReleaseSafe`, from any directory.
The well-known test key is for demonstrations only. Nothing is broadcast.
"""

import ctypes as C
from pathlib import Path
import sys

U8 = C.c_uint8
Word = U8 * 32


class AccessListItem(C.Structure):
    _fields_ = [
        ("address", U8 * 20),
        ("storage_keys", C.POINTER(Word)),
        ("storage_keys_len", C.c_size_t),
    ]


class Transaction(C.Structure):
    _fields_ = [
        ("chain_id", C.c_uint64),
        ("nonce", C.c_uint64),
        ("max_priority_fee_per_gas", Word),
        ("max_fee_per_gas", Word),
        ("gas_limit", C.c_uint64),
        ("to", U8 * 20),
        ("has_to", U8),
        ("value", Word),
        ("data", C.POINTER(U8)),
        ("data_len", C.c_size_t),
        ("access_list", C.POINTER(AccessListItem)),
        ("access_list_len", C.c_size_t),
    ]


def main():
    root = Path(__file__).resolve().parents[2]
    name = "libethzig.1.dylib" if sys.platform == "darwin" else "libethzig.so.1"
    lib = C.CDLL(str(root / "zig-out" / "lib" / name))
    lib.eth_tx_sign_max_len.argtypes = [C.POINTER(Transaction)]
    lib.eth_tx_sign_max_len.restype = C.c_size_t
    lib.eth_tx_sign.argtypes = [C.POINTER(Transaction), C.POINTER(U8),
                                C.POINTER(U8), C.c_size_t, C.POINTER(C.c_size_t)]
    lib.eth_tx_sign.restype = C.c_int
    lib.eth_tx_hash.argtypes = [C.POINTER(U8), C.c_size_t, C.POINTER(U8)]
    lib.eth_tx_hash.restype = C.c_int

    # Reproduce the independently checked transaction in tests/c_api_test.c.
    key = Word.from_buffer_copy(bytes.fromhex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
    data = (U8 * 4)(0xA9, 0x05, 0x9C, 0xBB)
    tx = Transaction(chain_id=1, nonce=5, gas_limit=100_000, has_to=1,
                     to=(U8 * 20)(*([0xAA] * 20)), data=data, data_len=len(data),
                     max_priority_fee_per_gas=Word.from_buffer_copy((2_000_000_000).to_bytes(32, "big")),
                     max_fee_per_gas=Word.from_buffer_copy((50_000_000_000).to_bytes(32, "big")))
    capacity = lib.eth_tx_sign_max_len(C.byref(tx))
    if not capacity:
        raise RuntimeError("Invalid transaction")
    out, written = (U8 * capacity)(), C.c_size_t()
    error = lib.eth_tx_sign(C.byref(tx), key, out, capacity, C.byref(written))
    if error:
        raise RuntimeError(f"eth_tx_sign failed: {error}")
    tx_hash = Word()
    error = lib.eth_tx_hash(out, written.value, tx_hash)
    if error:
        raise RuntimeError(f"eth_tx_hash failed: {error}")
    expected = "7a8921f4543662f78b5ff4917258d8a32ce704a3df7dc9789b24000dce29afab"
    if bytes(tx_hash).hex() != expected:
        raise RuntimeError("Transaction vector mismatch")
    print("signed transaction: 0x" + bytes(out[:written.value]).hex())
    print("transaction hash:   0x" + bytes(tx_hash).hex())


if __name__ == "__main__":
    main()
