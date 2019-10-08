package tests

import (
	"testing"

	"github.com/v1xingyue/muggle0612/encdec"
)

func TestAESCBC(t *testing.T) {
	key := []byte("Ew5DkV45dwvfQgpdgKKviwfsbvKuRwhB")
	aes := encdec.NewAES(key)
	originBytes := []byte("hello world....")
	if encryptBytes, err := aes.EncryptCBC(originBytes); err == nil {
		t.Log(len(encryptBytes))
		t.Log(string(encryptBytes))

		if outBytes, err := aes.DecryptCBC(encryptBytes); err == nil {
			t.Log(len(outBytes))
			t.Log(string(outBytes))
		}
	}
	t.Error(".")
}
