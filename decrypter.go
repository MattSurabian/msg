/**
 * decrypter
 * The decrypter chunks out the cipher text into its relevant parts per the encryption
 * implementation and attempts to decrypt the secrets it contains.
 *
 * Once the parts of the cipherText have been identified, the decrypter loops through the
 * repeating perUserPayload portion until it finds the fingerprint of the current user's public
 * key in the first 20 bytes of the block. When found, it attempts to decrypt the payload using
 * NaCl, thus learning the key necessary to decrypt the main cipher text.
 */
package msg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"strconv"
)

// Constants which store magic numbers related to how the encrypted blob is constructed
const GCM_NONCE_START = 0
const GCM_NONCE_END = 12
const CTLENGTH_BLOCK_START = GCM_NONCE_END
const CTLENGTH_BLOCK_END = CTLENGTH_BLOCK_START + CTLENGTH_BLOCK_SIZE
const ENCRYPTED_GCM_KEY_BYTES = 48

// Because we call a method here, it cannot be a const
var perUserPaylodBytes = NACL_FINGERPRINT_BYTES + NACL_NONCE_BYTES + ENCRYPTED_GCM_KEY_BYTES

/**
 * Decrypt attempts to decrypt the underlying secret data as per the header comment
 */
func Decrypt(blob []byte, selfPubKey, selfPrivKey *[32]byte) (plainText []byte, err error) {
	gcmNonce := blob[GCM_NONCE_START:GCM_NONCE_END]
	ctlength, _ := strconv.Atoi(string(blob[CTLENGTH_BLOCK_START:CTLENGTH_BLOCK_END]))
	ctEndIndex := CTLENGTH_BLOCK_END + ctlength
	cipherText := blob[CTLENGTH_BLOCK_END:ctEndIndex]
	secretOwnerKeyEndIndex := ctEndIndex + NACL_KEY_BYTES
	secretOwnerPubKey := BytesToNACLKey(blob[ctEndIndex:secretOwnerKeyEndIndex])

	// Find an encrypted secret that we are able to decrypt by matching our public key
	// fingerprint with the first 20 bytes of the 92 byte payload
	var naclNonce *[24]byte
	var encryptedKey []byte
	ourFingerprint := GetNACLKeyFingerprint(selfPubKey)
	for i := secretOwnerKeyEndIndex; i < len(blob); i += perUserPaylodBytes {
		fingerPrintEndIndex := i + NACL_FINGERPRINT_BYTES
		nonceEndIndex := fingerPrintEndIndex + NACL_NONCE_BYTES
		keyEndIndex := nonceEndIndex + ENCRYPTED_GCM_KEY_BYTES
		chunkFingerprint := blob[i:fingerPrintEndIndex]
		// If the fingerprints match this chunk was made just for us :-)
		if bytes.Equal(ourFingerprint, chunkFingerprint) {
			naclNonce = BytesToNACLNonce(blob[fingerPrintEndIndex:nonceEndIndex])
			encryptedKey = blob[nonceEndIndex:keyEndIndex]
			break
		}
	}

	// Attempt to learn the GCM key and then use it to decrypt the cipherText
	gcmKey, ok := box.Open(nil, encryptedKey, naclNonce, secretOwnerPubKey, selfPrivKey)
	if !ok {
		err = errors.New("Error decrypting GCM key")
		return
	}

	block, err := aes.NewCipher(gcmKey)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	plainText, err = gcm.Open(nil, gcmNonce, cipherText, nil)
	if err != nil {
		return
	}

	return
}
