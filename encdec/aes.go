package encdec

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
)

// AES 加密对象
type AES struct {
	key []byte
}

// NewAES 返回一个AES 加解密对象
func NewAES(key []byte) *AES {
	keyLen := len(key)
	if keyLen != 24 && keyLen != 32 && keyLen != 64 {
		log.Fatal("AES KEY LEN MUST BE : 24,32,64 , pass : ", keyLen)
	}
	return &AES{key: key}
}

// EncryptCBC 加密字节流 , 从key中获取一块区域作为IV
func (a *AES) EncryptCBC(origData []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, a.key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// DecryptCBC 解密AES CBC 加密的字节流
func (a *AES) DecryptCBC(crytedByte []byte) ([]byte, error) {
	k := []byte(a.key)
	block, _ := aes.NewCipher(k)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	orig := make([]byte, len(crytedByte))
	blockMode.CryptBlocks(orig, crytedByte)
	orig = PKCS7UnPadding(orig)
	return orig, nil
}
