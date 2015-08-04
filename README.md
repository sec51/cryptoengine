### Build status

[![Build Status](https://travis-ci.org/sec51/cryptoengine.svg?branch=master)](https://travis-ci.org/sec51/cryptoengine)

### CryptoEngine package

This simplifies even further the usage of the NaCl crypto primitives,
by taking care of the Nonce part.
It uses a KDF, specifically HKDF to compute the nonces.
While this simplifies a lot the usage of the NaCl library, it has some
impact on performance, although small enough for common applications.
When you need performance, then we suggest to use directly the original
package: golang.org/x/crypto/nacl/box of which this is a wrapper.