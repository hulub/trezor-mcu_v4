trezor-crypto
=============

[![Build Status](https://travis-ci.org/trezor/trezor-crypto.svg?branch=master)](https://travis-ci.org/trezor/trezor-crypto)

Heavily optimized cryptography algorithms for embedded devices.

These include:
- AES/Rijndael encryption/decryption
- Big Number (256 bit) Arithmetics
- BIP32 Hierarchical Deterministic Wallets
- BIP39 Mnemonic code
- ECDSA signing/verifying (supports secp256k1 and nist256p1 curves,
  uses RFC6979 for deterministic signatures)
- ECDSA public key derivation + Base58 address representation
- HMAC-SHA256 and HMAC-SHA512
- PBKDF2
- RIPEMD-160
- SHA256/SHA512
- unit tests (using Check - check.sf.net; in tests.c)
- tests against OpenSSL (in test-openssl.c)

Distibuted under MIT License.
