/**
 * entropy
 * The entropy module provides a simple wrapper around the rand reader and ReadFull
 * to ensure the returned buffer is completely filled with cryptographically sound random
 * data. Helper methods are also provided to cast byte array data to proper nonce types
 * so it can be used in the necessary cryptographic method calls.
 */
package msg

import (
	"crypto/rand"
	"io"
	"log"
)

// gcm nonce size is 12 bytes (96 bits)
// Since the nonce length and space is large enough,
// and a new key is used every time Encrypt is called
// enforcing nonce uniqueness should not be necessary
const GCM_NONCE_BYTES = 12

// NaCl nonce size is 24 bytes per spec
const NACL_NONCE_BYTES = 24

/**
 * ReadFromRand
 * Return a byte array of size numBytes that is completely full of cryptographically
 * sound random data.
 */
func ReadFromRand(numBytes int) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		log.Fatal(err)
	}
	return randomBytes
}

/**
 * GenerateGCMNonce
 * Generate a random nonce for use with AES GCM
 */
func GenerateGCMNonce() []byte {
	return ReadFromRand(GCM_NONCE_BYTES)
}

/**
 * GenerateNACLNonce
 * Generate a random nonce for use with NaCl
 */
func GenerateNACLNonce() *[24]byte {
	return BytesToNACLNonce(ReadFromRand(NACL_NONCE_BYTES))
}

/**
 * BytesToNACLNonce
 * Read in a byte array and attempt to cast it to *[24]byte for use with
 * NACL as a Nonce.
 */
func BytesToNACLNonce(bytes []byte) *[24]byte {
	if len(bytes) < NACL_NONCE_BYTES {
		log.Fatal("Too few bytes! This does not appear to be a valid NACL Nonce")
	}
	var naclNonce [NACL_NONCE_BYTES]byte
	copy(naclNonce[:], bytes[:])
	return &naclNonce
}
