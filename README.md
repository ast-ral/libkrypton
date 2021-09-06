# libkrypton

It's a toy cryptography library.

## Security

It should theoretically be correctly implemented and resistant against timing
attacks. However, you have no assurances of it being actually secure without
proper auditing. You should never use this in production for that reason.

## Algorithms

This library implements various algorithms:
* ChaCha20, a 256-bit security level stream cipher and pseudorandom entropy source
* Poly1305, a ~100-bit security level MAC / authenticator
* X25519, a 128-bit security level Diffie-Hellman key exchange over the Curve25519 elliptic curve
* Ed25519, a 128-bit security level digital signature over the Edwards25519 elliptic curve
* SHA-2, a family of hash functions targeting multiple security levels

## Support for no_std

This library has `#![no_std]` support if compiled with the `std` default feature disabled.

## Random values

In the case that you end up using this library:
1. Reconsider your life choices.
2. Consider using the [getrandom](https://crates.io/crates/getrandom) or the
   [rand](https://crates.io/crates/rand) crates to generate random values, as
   libkrypton provides no way to securely generate random values for use as
   private keys.
