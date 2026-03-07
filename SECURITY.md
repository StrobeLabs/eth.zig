# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in eth.zig, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@strobelabs.com** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

eth.zig includes cryptographic primitives (secp256k1 ECDSA, Keccak-256, BIP-32/39/44). Security issues in these components are treated as critical.

Areas of particular concern:

- **Private key handling** -- memory leaks, timing attacks, improper zeroing
- **Signature generation** -- RFC 6979 nonce generation, low-S normalization
- **Transaction signing** -- replay protection, chain ID encoding
- **ABI encoding/decoding** -- buffer overflows, incorrect padding

## Recognition

We credit reporters in the CHANGELOG (with permission) when a vulnerability is confirmed and fixed.
