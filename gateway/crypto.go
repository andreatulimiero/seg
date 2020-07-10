/*
Copyright (c) 2020, ETH and Andrea Tulimiero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package gateway

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/aead/cmac"
)

// getCMAC returns the CMAC of buf using AES-256 keyed with key
func getCMAC(buf []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	h, err := cmac.NewWithTagSize(c, len(key))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// getCBCMAC returns the CBC-MAC of buf using AES-256 keyed with key
func getCBCMAC(buf []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		LogFatal("Error getting cipher for CBC-MAC", "err", err)
	}
	padLen := 0
	if len(buf)%aes.BlockSize != 0 {
		padLen = len(buf) % aes.BlockSize
	}
	padding := make([]byte, padLen)
	plaintext := append(buf, padding...)
	mac := make([]byte, len(buf))
	iv := bytes.Repeat([]byte{0x0}, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(mac, plaintext)
	return mac, nil
}