package msg

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	userAPublicKey := ReadNACLKeyFile("testdata/a_public.key")
	userBPublicKey := ReadNACLKeyFile("testdata/b_public.key")

	selfPrivKey := ReadNACLKeyFile("testdata/a_private.key")
	selfPubKey := userAPublicKey

	plainText := []byte("I enjoy sport")
	authorizedUserKeys := []*[32]byte{userAPublicKey, userBPublicKey}
	blob1 := Encrypt(plainText, authorizedUserKeys, selfPrivKey, selfPubKey)
	blob2 := Encrypt(plainText, authorizedUserKeys, selfPrivKey, selfPubKey)

	if bytes.Equal(blob1, blob2) {
		t.Errorf("Encryption is deterministic!")
	}
}
