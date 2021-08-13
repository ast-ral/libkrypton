# libkrypton

libkrypton is my toy cryptography library.

## security

It's strongly not recommended to ever use this, as it's completely unaudited.
Theoretically, it should be correctly implemented and resistant against
side-channel attacks such as timing attacks.

## algorithms

libkrypton implements various algorithms including:
* ChaCha20, a 256-bit strong stream cipher and entropy source
* Poly1305, a ~100-bit strong MAC / authenticator
* X25519, a 128-bit strong Diffie-Hellman key exchange over the Curve25519 elliptic curve
