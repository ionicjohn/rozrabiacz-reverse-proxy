package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)


func encrypt(key []byte, plaintext []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}


	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func decrypt(key []byte, ciphertext []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
 		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)


	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}
