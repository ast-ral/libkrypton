# libkrypton

It's a toy cryptography library.

## Security

It's strongly recommended to never use this, as it's completely unaudited.
Theoretically, it should be correctly implemented and resistant against
side-channel attacks such as timing attacks.

## Algorithms

This library implements various algorithms:
* ChaCha20, a 256-bit security level stream cipher and pseudorandom entropy source
* Poly1305, a ~100-bit security level MAC / authenticator
* X25519, a 128-bit security level Diffie-Hellman key exchange over the Curve25519 elliptic curve
* Ed25519, a 128-bit security level digital signature over the Edwards25519 elliptic curve
* SHA-2, a family of hash functions targeting multiple security levels
