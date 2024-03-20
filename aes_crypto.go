package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
)

func aesEncrypt(plaindata []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	plaindata = PKCS5Padding(plaindata, block.BlockSize())
	cipherdata := make([]byte, len(plaindata))
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, key, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherdata, plaindata)
	cipherdata = append(iv, cipherdata...)
	return cipherdata, key, nil
}

func aesDecrypt(cipherdata []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := cipherdata[:aes.BlockSize]
	cipherdata = cipherdata[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaindata := make([]byte, len(cipherdata))
	mode.CryptBlocks(plaindata, cipherdata)
	plaindata = PKCS5UnPadding(plaindata)
	return plaindata, nil
}

func PKCS5Padding(cipherdata []byte, blockSize int) []byte {
	padding := blockSize - len(cipherdata)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherdata, padtext...)
}

func PKCS5UnPadding(plaindata []byte) []byte {
	length := len(plaindata)
	unpadding := int(plaindata[length-1])
	return plaindata[:(length - unpadding)]
}
