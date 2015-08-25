/**
 * keys
 * This module handles all the key generation logic for NaCl and AES.
 * It passes off reading from the rand reader to the entropy module to
 * limit code duplication. It also provides helper methods to turn byte
 * array data into the proper key types so they can be used in the crypto
 * methods where they are needed, and read and write key files to disk.
 */
package msg

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"log"
	"os"
)

// Consts used in this module
const PBKDF2_SALT_BYTES = 32
const PBKDF2_PASSWORD_BYTES = 32
const PBKDF2_KEY_BYTES = 32
const PBKDF2_CYCLES = 5000

// Include getters to make it clear other modules within cryptoUtils are using
// these constants
const NACL_FINGERPRINT_BYTES = 20

func getNACLFingerprintLength() int {
	return NACL_FINGERPRINT_BYTES
}

const NACL_KEY_BYTES = 32

/**
 * GenAES256Key
 * Generate a completley random 32 byte key using PBKDF2 with a completely random
 * "passphrase" and salt. sha256 is being used as the hashing function.
 */
func GenAES256Key() []byte {
	password := ReadFromRand(PBKDF2_PASSWORD_BYTES)
	salt := ReadFromRand(PBKDF2_SALT_BYTES)

	return pbkdf2.Key(password, salt, PBKDF2_CYCLES, PBKDF2_KEY_BYTES, sha256.New)
}

/**
 * GenerateNACLKeyPair
 * Helper method that wraps NaCl's built in key generation function.
 */
func GenerateNACLKeyPair() (pubKey, privKey *[32]byte) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return
}

/**
 * WriteNACLKeyFile
 * Helper method that encodes NACL keys to base64 then writes them to disk.
 */
func WriteNACLKeyFile(keyFilePath string, key *[32]byte, keyComment string, perms os.FileMode) {
	encodedKey := base64.StdEncoding.EncodeToString(key[:])

	err := ioutil.WriteFile(keyFilePath, []byte(encodedKey + keyComment), perms)
	if err != nil {
		log.Fatal(err)
	}
}

/**
 * ReadNACLKeyFile
 * Helper method to read NACL key files that were written to disk with WriteNACLKeyFile.
 */
func ReadNACLKeyFile(keyFilePath string) string {
	keyFile, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.Fatal(err)
	}

	return string(keyFile)
}

/**
 * NACLKeyFromFile
 * Helper method that reads files containing an NaCl key string and returns an NaCl key.
 */
func NACLKeyFromFile(filePath string) *[32]byte {
	return StringToNACLKey(ReadNACLKeyFile(filePath))
}

/**
 * StringToNACLKey
 * Helper method to read encoded NACL key data strings and return an NACL key.
 * Because this is a helper method, we assume the string passed in is encoded
 * as base64.
 */
func StringToNACLKey(encodedKeyString string) *[32]byte {
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKeyString[:44])
	if err != nil {
		log.Fatal(err)
	}

	naclKey := BytesToNACLKey(keyBytes)
	return naclKey
}

/**
 * GetNACLKeyFingerprint
 * Generates 20 byte fingerprints for NaCl Keys using sha1
 * This is only meant to be used with PUBLIC keys.
 */
func GetNACLKeyFingerprint(key *[32]byte) []byte {
	h := sha1.New()
	h.Write(key[:])
	return h.Sum(nil)
}

/**
 * BytesToNACLKey
 * Helper that takes in a byte array and casts it to *[32]byte so it can be used
 * as an NACL key. This is used by ReadNACLKeyFile.
 */
func BytesToNACLKey(bytes []byte) *[32]byte {
	if len(bytes) < 32 {
		log.Fatal("Too few bytes! This does not appear to be a valid NACL Key")
	}
	var naclKey [32]byte
	copy(naclKey[:], bytes[:])
	return &naclKey
}
