package cryptoengine

import (
	"encoding/hex"
	"strconv"
	"testing"
)

func TestHKDFDerivation(t *testing.T) {

	engine, err := InitCryptoEngine("test-engine")
	if err != nil {
		t.Fatal(err)
	}

	var previousKeys [100]string
	var derivedKey [nonceSize]byte

	for i := 0; i < 100; i++ {
		derivedKey, err = deriveNonce(engine.nonceKey, engine.salt, engine.context, strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}

		derivedKeyHex := hex.EncodeToString(derivedKey[:])

		for _, prevKey := range previousKeys {
			if derivedKeyHex == prevKey {
				t.Fatal("HKDF has generated a duplicated nonce !!!")
			}
		}

		previousKeys[i] = derivedKeyHex
	}

}
