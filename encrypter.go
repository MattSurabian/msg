/**
 * encrypter
 *
 * The encrypter utilizes two different forms of authenticated encryption to protect data:
 * AES256-GCM and NaCl
 *
 * TWO TYPES OF ENCRYPTION!?
 * Yes, but they are NOT used on top of one another. Each technology is used independently and
 * their outputs are combined into a large cipher text blob which provides secure data sharing
 * among many individuals without requiring out of band passphrase sharing, something
 * neither encryption technology is able of achieving on its own.
 *
 * WHAT IS GCM USED FOR?
 * GCM is used to secure the actual plain text which is passed into the Encrypt method.
 * The required 32 byte AES key is generated randomly, as is the 12 byte nonce.
 *
 * WHAT IS NaCl USED FOR?
 * NaCl is used to allow the "owner" of the secret data to secure the random 32 byte key used
 * in AES256-GCM by encrypting it with each authorized user's public key.
 *
 * HOW IS THE CIPHER TEXT BLOB CONSTRUCTED?
 * The beginning of the cipher text blob contains all of the GCM encryption information along with
 * the public key of the secret creator:
 *
 *    gcmNonce(12 bytes) cipherTextLength(10 bytes) cipherText(? bytes) pubKeyOfSecretCreator(32 bytes)
 *
 * The remainder of the blob is made up of repeating 92 byte chunks containing the
 * NaCl encrypted AES256-GCM key prefixed with the fingerprint of the public key used for encryption
 * and a unique nonce:
 *
 *    usersPubKeyFingerprint(20 bytes) NaClNonce(24 bytes) NaClSecret(48 bytes)
 */
package msg

import (
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/nacl/box"
	"log"
	"strconv"
)

// Always store ctLength in a fixed size block. This should be large
// enough to capture the ctLength for VERY large files. GCM should be
// capable of securing terrabytes of data without the need for a key change.
// This block size must be fixed in order for us to predictably
// chop up the cipher text when we try to decrypt
const CTLENGTH_BLOCK_SIZE = 16

/**
 * Encrypt returns a byte array which is constructed per the header comments
 */
func Encrypt(plainText []byte, authorizedPubKeys []*[32]byte, selfPubKey, selfPrivKey *[32]byte) []byte {
	aesKey := GenAES256Key()
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	var blob []byte
	gcmNonce := GenerateGCMNonce()

	blob = append(blob, gcmNonce...)

	cipherText := gcm.Seal(nil, gcmNonce, plainText, nil)

	// Make sure we can fit the length of the cipher text in our fixed size length block
	stringCTLength := strconv.Itoa(len(cipherText))
	if len(stringCTLength) > CTLENGTH_BLOCK_SIZE {
		panic("Data too large. Refusing to encrypt")
	}

	for l := len(stringCTLength); l < CTLENGTH_BLOCK_SIZE; l++ {
		// pad with 0's
		stringCTLength = "0" + stringCTLength
	}
	ctLen := []byte(stringCTLength)

	blob = append(blob, ctLen[:]...)
	blob = append(blob, cipherText...)
	blob = append(blob, selfPubKey[:]...)

	// Encrypt the aesKey for each authorized user with NaCl
	for _, pk := range authorizedPubKeys {
		naclNonce := GenerateNACLNonce()
		encryptedGCMKey := box.Seal(nil, aesKey, naclNonce, pk, selfPrivKey)
		keyFingerPrint := GetNACLKeyFingerprint(pk)

		blob = append(blob, keyFingerPrint...)
		blob = append(blob, naclNonce[:]...)
		blob = append(blob, encryptedGCMKey...)
	}

	return blob
}
