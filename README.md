### Build status

[![Build Status](https://travis-ci.org/sec51/cryptoengine.svg?branch=master)](https://travis-ci.org/sec51/cryptoengine)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/sec51/cryptoengine/)

### CryptoEngine package

This simplifies even further the usage of the NaCl crypto primitives,
by taking care of the `nonce` part.
It uses a KDF, specifically HKDF to compute the nonces.

### Usage

1- Import the library

```
import github.com/sec51/cryptoengine
```

2- Instanciate the `CryptoEngine` object via:

```
	engine, err := cryptoengine.InitCryptoEngine("Sec51")
	if err != nil {
		return err
	}
```
See the godoc for more info about the InitCryptoEngine parameter

3- Encrypt a message using symmetric encryption

```
    message := "the quick brown fox jumps over the lazy dog"
	engine.NewMessage(message)
	if err != nil {
		return err
	}
```

4- Serialize the message to a byte slice, so that it can be safely sent to the network

```
	messageBytes, err := tcp.ToBytes()
	if err != nil {
		t.Fatal(err)
	}	
```

5- Parse the byte slice back to a message

```
	message, err := MessageFromBytes(messageBytes)
	if err != nil {
		t.Fatal(err)
	}
```

