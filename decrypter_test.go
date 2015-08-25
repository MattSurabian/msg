package msg

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var largeDataTestBytes = 10000000 // 10MB
var largeDataTestFilePath = "testdata/largeRandomDataFile.txt"

func TestDecrypt(t *testing.T) {
	userAPublicKey := NACLKeyFromFile("testdata/a_public.key")
	userBPublicKey := NACLKeyFromFile("testdata/b_public.key")
	authorizedUserKeys := []*[32]byte{userAPublicKey, userBPublicKey}

	selfPrivKey := NACLKeyFromFile("testdata/a_private.key")
	selfPubKey := userAPublicKey

	writeLargeRandomDataFile()
	cases := []struct {
		plainText []byte
	}{
		{[]byte("Corporations are people, my friend")},
		{readLargeRandomDataFile()},
	}
	for _, c := range cases {
		blob := Encrypt(c.plainText, authorizedUserKeys, selfPubKey, selfPrivKey)
		decryptedText, err := Decrypt(blob, selfPubKey, selfPrivKey)
		if err != nil || !bytes.Equal(c.plainText, decryptedText) {
			t.Errorf("Encryption/Decryption relationship is broken.")
		}

	}
	deleteLargeRandomDataFile()
}

func writeLargeRandomDataFile() {
	garbageData := ReadFromRand(largeDataTestBytes)
	encodedKey := base64.StdEncoding.EncodeToString(garbageData[:])
	err := ioutil.WriteFile(largeDataTestFilePath, []byte(encodedKey), 0777)
	if err != nil {
		log.Fatal(err)
	}
}

func readLargeRandomDataFile() []byte {
	garbageDataBytes, err := ioutil.ReadFile(largeDataTestFilePath)
	if err != nil {
		log.Fatal(err)
	}

	largeGarbageData, err := base64.StdEncoding.DecodeString(string(garbageDataBytes))
	if err != nil {
		log.Fatal(err)
	}

	return largeGarbageData
}

func deleteLargeRandomDataFile() {
	err := os.Remove(largeDataTestFilePath)
	if err != nil {
		log.Fatal(err)
	}
}
