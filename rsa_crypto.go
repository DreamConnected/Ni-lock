package main

import (
	"crypto/rand"
	"crypto/rsa"
)

/*
func readRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func readRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
*/

/*
"I have 3 functions that I don't use,
I don't use those without nested if statements,
I don't use those that are highly readable,
And I didn't write it by myself."
*/

func rsaEncrypt(plaindata []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	cipherdata, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaindata)
	if err != nil {
		return nil, err
	}
	return cipherdata, nil
}

func rsaDecrypt(cipherdata []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plaindata, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherdata)
	if err != nil {
		return nil, err
	}
	return plaindata, nil
}
