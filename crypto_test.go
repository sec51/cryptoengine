package cryptoengine

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

func TestSecretKeyEncryption(t *testing.T) {
	message := []byte("The quick brown fox jumps over the lazy dog")

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

	tcp, err := engine.NewMessage(message)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := tcp.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

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
	storedMessage, err := MessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if storedMessage.version != tcp.version {
		t.Error("Message version mismacth")
	}

	if storedMessage.length != tcp.length {
		t.Error("Message length mismacth")
	}

	if bytes.Compare(storedMessage.nonce[:], tcp.nonce[:]) != 0 {
		t.Error("Message nonce mismacth")
	}

	if bytes.Compare(storedMessage.message[:], tcp.message[:]) != 0 {
		t.Error("Message nonce mismacth")
	}

	decrypted, err := enginePeer.Decrypt(storedMessage, nil)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if string(decrypted) != string(message) {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	message := []byte("The quick brown fox jumps over the lazy dog")

	firstEngine, err := InitCryptoEngine("Sec51Peer1")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	secondEngine, err := InitCryptoEngine("Sec51Peer2")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	tcp, err := firstEngine.NewMessageToPubKey(message, secondEngine.PublicKey())
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := tcp.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

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
	storedMessage, err := MessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if storedMessage.version != tcp.version && tcp.version != publicKeyVersion {
		t.Error("Message version mismacth")
	}

	if storedMessage.length != tcp.length {
		t.Error("Message length mismacth")
	}

	if bytes.Compare(storedMessage.nonce[:], tcp.nonce[:]) != 0 {
		t.Error("Message nonce mismacth")
	}

	if bytes.Compare(storedMessage.message[:], tcp.message[:]) != 0 {
		t.Error("Message nonce mismacth")
	}

	decrypted, err := secondEngine.Decrypt(storedMessage, firstEngine.PublicKey())
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if string(decrypted) != string(message) {
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
	removeFolder(keyPath)
}
