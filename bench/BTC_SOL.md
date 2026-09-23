# BTC P2WPKH and SOL SLIP-0010

Address derivation from a BIP-39 seed. Not part of the alloy.rs comparison (`bench/RESULTS.md`); alloy has no BIP-84 P2WPKH or SLIP-0010 Solana path.

## Sibling crate (measured)

[hd.zig](https://github.com/Macho0x/hd.zig) — `zig build bench`, ReleaseFast, Linux x86_64, Zig 0.16.0, 5000 rounds, seed computed once:

| Path | ns/op | µs/op |
|---|---:|---:|
| BTC BIP-84 P2WPKH `m/84'/0'/0'/0/0` | 363,330 | 363 |
| SOL SLIP-0010 `m/44'/501'/0'/0'` | 169,473 | 169 |

BTC there uses an 8-bit generator comb and 5×52 field mul. SOL is HMAC-SHA512 SLIP-0010 plus std Ed25519 (same algorithm as `src/sol.zig` here).

## This repo

`zig build bench` now prints `btc_p2wpkh` and `sol_slip10`.

In-tree BTC reuses `hd_wallet.deriveBtcAccount` and std `Secp256k1.basePoint.mul` (same as existing BIP-32 `deriveChild`), not the 5×52 comb. Expect BTC ns/op closer to a few hundred microseconds–milliseconds until pubkey-create goes through the vendored libsecp256k1 backend. SOL should be in the same ballpark as the table above.
