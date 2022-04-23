package cryptoengine

import (
	"bytes"
	"math"

	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNonceGeneration(t *testing.T) {
	engine, err := InitCryptoEngine("test")
	assert.Nil(t, err)
	assert.NotNil(t, engine)

	nonce, err := engine.generateNonce()
	assert.Nil(t, err)
	assert.True(t, nonce > 0 && nonce < math.MaxUint64)

	nonce, err = engine.generateNonce()
	assert.Nil(t, err)
	assert.True(t, nonce > 0 && nonce < math.MaxUint64)
}

func TestSecretKeyEncryption(t *testing.T) {

	message, err := NewMessage("The quick brown fox jumps over the lazy dog", 1)
	if err != nil {
		t.Fatal(err)
	}

	enginePeer, err := InitCryptoEngine("Sec51")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	engine, err := InitCryptoEngine("Sec51")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	encryptedMessage, err := engine.NewEncryptedMessage(message)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := encryptedMessage.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// temporary write the corpus for fuzzing
	// writeFile("corpus/4", messageBytes)

	// simulate writing to network
	var buffer bytes.Buffer
	buffer.Write(messageBytes)

	// read the bytes back
	storedData, err := ioutil.ReadAll(&buffer)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// parse the bytes
	storedMessage, err := encryptedMessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// check the encrypted message data if it matches
	if storedMessage.length != encryptedMessage.length {
		t.Error("Encrypted Message length mismacth")
	}

	if bytes.Compare(storedMessage.nonce[:], encryptedMessage.nonce[:]) != 0 {
		t.Error("Encrypted  Message nonce mismacth")
	}

	if bytes.Compare(storedMessage.data[:], encryptedMessage.data[:]) != 0 {
		t.Error("Encrypted Message data mismacth")
	}

	decrypted, err := enginePeer.Decrypt(messageBytes)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if decrypted.Type != message.Type {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}

	if decrypted.Version != message.Version {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}

	if decrypted.Text != message.Text {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	message, err := NewMessage("The quick brown fox jumps over the lazy dog", 1)
	if err != nil {
		t.Fatal(err)
	}

	firstEngine, err := InitCryptoEngine("Sec51Peer1")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}
	// test the verification engine
	firstVerificationEngine, err := NewVerificationEngine("Sec51Peer1")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	secondEngine, err := InitCryptoEngine("Sec51Peer2")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}
	// test the verification engine
	secondVerificationEngine, err := NewVerificationEngine("Sec51Peer2")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	encryptedMessage, err := firstEngine.NewEncryptedMessageWithPubKey(message, secondVerificationEngine)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := encryptedMessage.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// temporary write the corpus for fuzzing
	// writeFile("corpus/5", messageBytes)

	// simulate writing to network
	var buffer bytes.Buffer
	buffer.Write(messageBytes)

	// read the bytes back
	storedData, err := ioutil.ReadAll(&buffer)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// parse the bytes
	storedMessage, err := encryptedMessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// check the encrypted message data if it matches
	if storedMessage.length != encryptedMessage.length {
		t.Error("Encrypted Message length mismacth")
	}

	if bytes.Compare(storedMessage.nonce[:], encryptedMessage.nonce[:]) != 0 {
		t.Error("Encrypted  Message nonce mismacth")
	}

	if bytes.Compare(storedMessage.data[:], encryptedMessage.data[:]) != 0 {
		t.Error("Encrypted Message data mismacth")
	}

	decrypted, err := secondEngine.DecryptWithPublicKey(storedData, firstVerificationEngine)

	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if decrypted.Version != message.Version {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

	if decrypted.Type != message.Type {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

	if decrypted.Text != message.Text {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

}

func TestSanitization(t *testing.T) {

	id := "S E C	51"

	sanitized := sanitizeIdentifier(id)
	if strings.Contains(sanitized, " ") {
		t.Error("The sanitization function does not remove spaces")
	}

	if strings.Contains(sanitized, "\t") {
		t.Error("The sanitization function does not remove tabs")
	}

}

func cleanUp() {
	//removeFolder(keyPath)
}
