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
	"errors"
	"fmt"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
)

var (
	cryptoHandshakeError = errors.New("cryptoHandshakeComplete not yet true")
	PeerIsMigratingError = errors.New("peer is migrating")
)

type readerFromAddr interface {
	ReadFrom([]byte) (int, net.Addr, error)
}

// eConn is an encrypted snet.Conn
type eConn struct {
	peer *peer
	conn *snet.Conn
}

func newEConn(conn *snet.Conn, peer *peer) *eConn {
	return &eConn{conn: conn, peer: peer}
}

func (e *eConn) writeTo(b []byte, raddr net.Addr) (int, error) {
	if !e.peer.cryptoHandshakeComplete {
		return -1, cryptoHandshakeError
	}
	if e.peer.pathMgr.isMigrating == 1 {
		return -1, PeerIsMigratingError
	}
	block := e.peer.keyMgr.block
	padLen := aes.BlockSize - (len(b) % aes.BlockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plaintext := append(b, padding...)
	mode := cipher.NewCBCEncrypter(block, e.peer.keyMgr.iv)
	mode.CryptBlocks(plaintext, plaintext)
	return e.conn.WriteTo(plaintext, raddr)
}

func (e *eConn) Write(b []byte) (int, error) {
	return e.writeTo(b, e.conn.RemoteAddr())
}

func (e *eConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, raddr, err := e.conn.ReadFrom(buf)
	if err != nil {
		return -1, nil, err
	}
	if !e.peer.cryptoHandshakeComplete {
		return -1, nil, fmt.Errorf("cryptoHandshakeComplete not yet true")
	}
	block := e.peer.keyMgr.block
	ciphertext := buf[:n]
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return -1, nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}
	mode := cipher.NewCBCDecrypter(block, e.peer.keyMgr.iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	padLen := int(ciphertext[n-1])
	dataLen := n - padLen
	buf = ciphertext[:dataLen]
	return dataLen, raddr, nil
}
