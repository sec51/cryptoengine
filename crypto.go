package cryptoengine

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/sec51/convert/bigendian"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"log"
	"math"
	"net/url"
	"regexp"
	"strings"
)

const (
	secretKeyVersion    = 0  // this is the symmetric encryption version
	publicKeyVersion    = 1  // this is the asymmetric encryption version
	nonceSize           = 24 // this is the nonce size, required by NaCl
	keySize             = 32 // this is the nonce size, required by NaCl
	rotateSaltAfterDays = 2  // this is the amount of days the salt is valid - if it crosses this amount a new salt is generated
)

var (
	KeySizeError           = errors.New(fmt.Sprintf("The provisioned key size is less than: %d\n", keySize))
	KeyNotValidError       = errors.New("The provisioned public key is not valid")
	SaltGenerationError    = errors.New("Could not generate random salt")
	KeyGenerationError     = errors.New("Could not generate random key")
	MessageDecryptionError = errors.New("Could not verify the message. Message has been tempered with!")
	MessageParsingError    = errors.New("Could not parse the Message from bytes")
	messageEmpty           = errors.New("Can not encrypt an empty message")
	whiteSpaceRegEx        = regexp.MustCompile("\\s")
	emptyKey               = make([]byte, keySize)

	// salt for derivating keys
	saltSuffixFormat = "%s_salt.key" // this is the salt file,for instance: sec51_salt.key

	// secret key for symmetric encryption
	secretSuffixFormat = "%s_secret.key" // this is the secret key crypto file, for instance: sec51_secret.key

	// asymmetric keys
	publicKeySuffixFormat = "%s_public.key"  // this is the public key crypto file,for instance: sec51_public.key
	privateSuffixFormat   = "%s_private.key" // this is the private key crypto file,for instance: sec51_priovate.key

	// nonce secret key
	nonceSuffixFormat = "%s_nonce.key" // this is the secret key crypto file used for generating nonces,for instance: sec51_nonce.key
)

// This is the basic object which needs to be instanciated for encrypting messages
// either via public key cryptography or private key cryptography
// The object has the methods necessary to execute all the needed functions to encrypt and decrypt a message, both with symmetric and asymmetric
// crypto
type CryptoEngine struct {
	context              string        // this is the context used for the key derivation function and for namespacing the key files
	publicKey            [keySize]byte // cached asymmetric public key
	privateKey           [keySize]byte // cached asymmetric private key
	secretKey            [keySize]byte // secret key used for symmetric encryption
	peerPublicKey        [keySize]byte // the peer symmetric public key
	sharedKey            [keySize]byte // this is the precomputed key, between the peer aymmetric public key and the application asymmetric private key. This speeds up things.
	salt                 [keySize]byte // salt for deriving the random nonces
	nonceKey             [keySize]byte // this key is used for deriving the random nonces. It's different from the privateKey
	preSharedInitialized bool          // flag which tells if the preSharedKey has been initialized
}

// This function initialize all the necessary information to carry out a secure communication
// either via public key cryptography or secret key cryptography.
// The peculiarity is that the user of this package needs to take care of only one parameter, the communicationIdentifier.
// It defines a unique set of keys between the application and the communicationIdentifier unique end point.
// IMPORTANT: The parameter communicationIdentifier defines several assumptions the code use:
// - it names the secret key files with the comuncationIdentifier prefix. This means that if you want to have different secret keys
//   with different end points, you can differrentiate the key by having different unique communicationIdentifier.
//   It, also, loads the already created keys back in memory based on the communicationIdentifier
// - it does the same with the asymmetric keys
// The communicationIdentifier parameter is URL unescape, trimmed, set to lower case and all the white spaces are replaced with an underscore.
// The publicKey parameter can be nil. In that case the CryptoEngine assumes it has been instanciated for symmetric crypto usage.
func InitCryptoEngine(communicationIdentifier string) (*CryptoEngine, error) {
	// define an error object
	var err error
	// create a new crypto engine object
	ce := new(CryptoEngine)
	ce.preSharedInitialized = false

	// sanitize the communicationIdentifier
	ce.context = sanitizeIdentifier(communicationIdentifier)

	// load or generate the salt
	salt, err := loadSalt(ce.context)
	if err != nil {
		return nil, err
	}
	ce.salt = salt

	// load or generate the corresponding public/private key pair
	ce.publicKey, ce.privateKey, err = loadKeyPairs(ce.context)
	if err != nil {
		return nil, err
	}

	// load or generate the secret key
	secretKey, err := loadSecretKey(ce.context)
	if err != nil {
		return nil, err
	}
	ce.secretKey = secretKey

	// load the nonce key
	nonceKey, err := loadNonceKey(ce.context)
	if err != nil {
		return nil, err
	}
	ce.nonceKey = nonceKey

	// finally return the CryptoEngine instance
	return ce, nil

}

// this function reads nonceSize random data
func generateSalt() ([keySize]byte, error) {
	var data32 [keySize]byte
	data := make([]byte, keySize)
	_, err := rand.Read(data)
	if err != nil {
		return data32, err
	}
	total := copy(data32[:], data)
	if total != keySize {
		return data32, SaltGenerationError
	}
	return data32, nil
}

// this function reads keySize random data
func generateSecretKey() ([keySize]byte, error) {
	var data32 [keySize]byte
	data := make([]byte, keySize)
	_, err := rand.Read(data)
	if err != nil {
		return data32, err
	}
	total := copy(data32[:], data[:keySize])
	if total != keySize {
		return data32, KeyGenerationError
	}
	return data32, nil
}

// load the salt random bytes from the id_salt.key
// if the file does not exist, create a new one
// if the file is older than N days (default 2) generate a new one and overwrite the old
// TODO: rotate the salt file
func loadSalt(id string) ([keySize]byte, error) {

	var salt [keySize]byte

	saltFile := fmt.Sprintf(saltSuffixFormat, id)
	if keyFileExists(saltFile) {
		return readKey(saltFile, keysFolderPrefixFormat)
	}

	// generate the random salt
	salt, err := generateSalt()
	if err != nil {
		return salt, err
	}

	// write the salt to the file with its prefix
	if err := writeKey(saltFile, keysFolderPrefixFormat, salt[:]); err != nil {
		return salt, err
	}

	// return the salt and no error
	return salt, nil
}

// load the key random bytes from the id_secret.key
// if the file does not exist, create a new one
func loadSecretKey(id string) ([keySize]byte, error) {

	var key [keySize]byte

	keyFile := fmt.Sprintf(secretSuffixFormat, id)
	if keyFileExists(keyFile) {
		return readKey(keyFile, keysFolderPrefixFormat)
	}

	// generate the random salt
	key, err := generateSecretKey()
	if err != nil {
		return key, err
	}

	// write the salt to the file with its prefix
	if err := writeKey(keyFile, keysFolderPrefixFormat, key[:]); err != nil {
		return key, err
	}

	// return the salt and no error
	return key, nil
}

// load the nonce key random bytes from the id_nonce.key
// if the file does not exist, create a new one
func loadNonceKey(id string) ([keySize]byte, error) {

	var nonceKey [keySize]byte

	nonceFile := fmt.Sprintf(nonceSuffixFormat, id)
	if keyFileExists(nonceFile) {
		return readKey(nonceFile, keysFolderPrefixFormat)
	}

	// generate the random salt
	nonceKey, err := generateSecretKey()
	if err != nil {
		return nonceKey, err
	}

	// write the salt to the file with its prefix
	if err := writeKey(nonceFile, keysFolderPrefixFormat, nonceKey[:]); err != nil {
		return nonceKey, err
	}

	// return the salt and no error
	return nonceKey, nil
}

// load the key pair, public and private keys, the id_public.key, id_private.key
// if the files do not exist, create them
// Returns the publicKey, privateKey, error
func loadKeyPairs(id string) ([keySize]byte, [keySize]byte, error) {

	var private [keySize]byte
	var public [keySize]byte
	var err error

	// try to load the private key
	privateFile := fmt.Sprintf(privateSuffixFormat, id)
	if keyFileExists(privateFile) {
		if private, err = readKey(privateFile, keysFolderPrefixFormat); err != nil {
			return public, private, err
		}
	}
	// try to load the public key and if it succeed, then return both the keys
	publicFile := fmt.Sprintf(publicKeySuffixFormat, id)
	if keyFileExists(publicFile) {
		if public, err = readKey(publicFile, keysFolderPrefixFormat); err != nil {
			return public, private, err
		}

		// if we reached here, it means that both the private and the public key
		// existed and loaded successfully
		return public, private, err
	}

	// if we reached here then, we need to cerate the key pair
	tempPublic, tempPrivate, err := box.GenerateKey(rand.Reader)

	// check for errors first, otherwise continue and store the keys to files
	if err != nil {
		return public, private, err
	}
	// dereference the pointers
	public = *tempPublic
	private = *tempPrivate

	// write the public key first
	if err := writeKey(publicFile, keysFolderPrefixFormat, public[:]); err != nil {
		return public, private, err
	}

	// write the private
	if err := writeKey(privateFile, keysFolderPrefixFormat, private[:]); err != nil {
		// delete the public key, otherwise we remain in an unwanted state
		// the delete can fail as well, therefore we print an error
		if err := deleteFile(publicFile); err != nil {
			log.Printf("[SEVERE] - The private key for asymmetric encryption, %s, failed to be persisted. \nWhile trying to cleanup also the public key previosuly stored, %s, the operation failed as well.\nWe are now in an unrecoverable state.Please delete both files manually: %s - %s", privateFile, publicFile, privateFile, publicFile)
			return public, private, err
		}
		return public, private, err
	}

	// return the data
	return public, private, err

}

// Sanitizes the input of the communicationIdentifier
// The input is URL unescape, trimmed, set to lower case and all the white spaces are replaced with an underscore.
// TODO: evaluate the QueryUnescape error
func sanitizeIdentifier(id string) string {
	// unescape in case it;s URL encoded
	unescaped, _ := url.QueryUnescape(id)
	// trim white spaces
	trimmed := strings.TrimSpace(unescaped)
	// make lower case
	lowered := strings.ToLower(trimmed)
	// replace the white spaces with _
	cleaned := whiteSpaceRegEx.ReplaceAllLiteralString(lowered, "_")
	return cleaned
}

// load or generate the salt

// This struct encapsulate the ecnrypted message in a TCP packet, in an easily parseable format
// We assume the data is always encrypted
// Format:
// |lenght| => 8 bytes (uint64 total message length)
// |version| => 4 bytes (int message version)
// |nonce| => 24 bytes ([]byte size)
// |message| => N bytes ([]byte message)
type Message struct {
	length  uint64          // total length of the packet
	version int             // version of the message, done to support backward compatibility
	nonce   [nonceSize]byte // the randomly created nonce. The nonce can be public.
	message []byte          // the encrypted message
}

// Gives access to the public key
func (engine *CryptoEngine) PublicKey() []byte {
	return engine.publicKey[:]
}

// This method accepts the message as byte slice, then encrypts it using a symmetric key
func (engine *CryptoEngine) NewEncryptedMessage(message []byte) (Message, error) {

	m := Message{}

	// check if the messageis nil
	if message == nil {
		return m, messageEmpty
	}

	// check if the message length is greather than zero
	if len(message) == 0 {
		return m, messageEmpty
	}

	// derive nonce
	nonce, err := deriveNonce(engine.nonceKey, engine.salt, engine.context)
	if err != nil {
		return m, err
	}

	m.version = secretKeyVersion
	m.nonce = nonce

	encryptedData := secretbox.Seal(nil, message, &m.nonce, &engine.secretKey)

	// assign the encrypted data to the message
	m.message = encryptedData

	// calculate the overall size of the message
	m.length = uint64(len(m.message) + len(m.nonce) + 4 + 4)

	return m, nil

}

// This method accepts the message as byte slice and the public key of the receiver of the messae,
// then encrypts it using the asymmetric key public key.
// If the public key is not privisioned and does not have the required length of 32 bytes it raises an exception.
func (engine *CryptoEngine) NewEncryptedMessageWithPubKey(message []byte, peerPublicKey []byte) (Message, error) {

	var peerPublicKey32 [keySize]byte

	m := Message{}

	// check if the messageis nil
	if message == nil {
		return m, messageEmpty
	}

	// check if the message length is greather than zero
	if len(message) == 0 {
		return m, messageEmpty
	}

	// // check if the public key was set
	if peerPublicKey == nil {
		return m, KeyNotValidError
	}

	// check the size of the peerPublicKey
	if len(peerPublicKey) != keySize {
		return m, KeyNotValidError
	}

	// check the peerPublicKey is not empty (all zeros)
	if bytes.Compare(peerPublicKey[:], emptyKey) == 0 {
		return m, KeyNotValidError
	}

	// verify the copy succeeded
	total := copy(peerPublicKey32[:], peerPublicKey[:keySize])
	if total != keySize {
		return m, KeyNotValidError
	}

	// assign the public key to peerPublicKey struct field
	engine.peerPublicKey = peerPublicKey32

	// derive nonce
	nonce, err := deriveNonce(engine.nonceKey, engine.salt, engine.context)
	if err != nil {
		return m, err
	}

	m.version = publicKeyVersion
	m.nonce = nonce

	// precompute the shared key, if it was not already
	if !engine.preSharedInitialized {
		box.Precompute(&engine.sharedKey, &engine.peerPublicKey, &engine.privateKey)
		engine.preSharedInitialized = true
	}
	encryptedData := box.Seal(nil, message, &m.nonce, &engine.peerPublicKey, &engine.privateKey)

	// assign the encrypted data to the message
	m.message = encryptedData

	// calculate the size of the message
	m.length = uint64(len(m.message))

	return m, nil

}

func (engine *CryptoEngine) Decrypt(m Message, otherPeerPublicKey []byte) ([]byte, error) {

	// decrypt with secretbox
	if m.version == secretKeyVersion {

		if decryptedMessage, valid := secretbox.Open(nil, m.message, &m.nonce, &engine.secretKey); !valid {
			return nil, MessageDecryptionError
		} else {
			return decryptedMessage, nil
		}
	}

	// check that the  otherPeerPublicKey is set at this point
	if otherPeerPublicKey == nil {
		return nil, KeyNotValidError
	}

	// Make sure the key has a valid size
	if len(otherPeerPublicKey) < keySize {
		return nil, KeyNotValidError
	}

	// copy the key
	if total := copy(engine.peerPublicKey[:], otherPeerPublicKey[:keySize]); total != keySize {
		return nil, KeyNotValidError
	}

	if engine.preSharedInitialized {
		return decryptWithPreShared(engine, m)
	}

	box.Precompute(&engine.sharedKey, &engine.peerPublicKey, &engine.privateKey)
	engine.preSharedInitialized = true

	return decryptWithPreShared(engine, m)

}

func decryptWithPreShared(engine *CryptoEngine, m Message) ([]byte, error) {
	if decryptedMessage, valid := box.OpenAfterPrecomputation(nil, m.message, &m.nonce, &engine.sharedKey); !valid {
		return nil, MessageDecryptionError
	} else {
		return decryptedMessage, nil
	}
}

// STRUCTURE
//    8		1	  24	  N
// |SIZE|VERSION|NONCE|  DATA  |
func (m Message) ToBytes() ([]byte, error) {
	if m.length > math.MaxUint64 {
		return nil, errors.New("The message exceeds the maximum allowed sized: uint64 MAX")
	}

	var buffer bytes.Buffer

	// length
	lengthBytes := bigendian.ToUint64(m.length)
	buffer.Write(lengthBytes[:])

	// version
	versionBytes := bigendian.ToInt(m.version)
	buffer.Write(versionBytes[:])

	// nonce
	buffer.Write(m.nonce[:])

	// message
	buffer.Write(m.message)

	return buffer.Bytes(), nil

}

func MessageFromBytes(data []byte) (Message, error) {

	var err error
	var versionData [4]byte
	var lengthData [8]byte
	var nonceData [nonceSize]byte
	minimumDataSize := 8 + 4 + nonceSize
	m := Message{}

	// check if the data is smaller than 36 which is the minimum
	if data == nil {
		return m, MessageParsingError
	}

	if len(data) < minimumDataSize+1 {
		return m, MessageParsingError
	}

	lenght := data[:8]
	version := data[8:12]
	nonce := data[12 : 12+nonceSize] // 24 bytes
	message := data[minimumDataSize:]

	total := copy(lengthData[:], lenght)
	if total != 8 {
		return m, MessageParsingError
	}

	total = copy(versionData[:], version)
	if total != 4 {
		return m, MessageParsingError
	}

	total = copy(nonceData[:], nonce)
	if total != nonceSize {
		return m, MessageParsingError
	}

	m.length = bigendian.FromUint64(lengthData)
	m.version = bigendian.FromInt(versionData)
	m.nonce = nonceData
	m.message = message
	return m, err
}
