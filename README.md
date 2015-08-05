### Build status

[![Build Status](https://travis-ci.org/sec51/cryptoengine.svg?branch=master)](https://travis-ci.org/sec51/cryptoengine)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/sec51/cryptoengine/)

### CryptoEngine package

This simplifies even further the usage of the NaCl crypto primitives,
by taking care of the Nonce part.
It uses a KDF, specifically HKDF to compute the nonces.

