package msg

import (
	"bytes"
	"testing"
)

func TestGenAES256Key(t *testing.T) {

	key1 := GenAES256Key()
	key2 := GenAES256Key()

	if bytes.Equal(key1, key2) {
		t.Errorf("Key generation is deterministic!")
	}

	// We want to use at least 32 byte keys so AES256 can be used
	if len(key1) < 32 {
		t.Errorf("The key length is less than 32 bytes!")
	}
}
