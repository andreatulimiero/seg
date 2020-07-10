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
	"github.com/monnand/dhkx"
	"sync"
)

type keyMgr struct {
	peer   *peer
	group  *dhkx.DHGroup
	priKey *dhkx.DHKey
	pubKey []byte
	key    []byte
	iv     []byte
	block  cipher.Block
	pubKeyCheckMutex sync.Mutex
}

func newKeyMgr(peer *peer) *keyMgr {
	return &keyMgr{peer: peer}
}

// initDataCrypto initializes data plane crypto structures
func (k *keyMgr) initDataCrypto(remotePubKey []byte) error {
	if len(k.key) != 0 { panic("Key was already initialized") }

	err := k.computeSharedKey(remotePubKey); if err != nil {
		return err
	}
	k.block, err = aes.NewCipher(k.key[:32])
	if err != nil {
		return err
	}
	k.iv = bytes.Repeat([]byte{0x0}, aes.BlockSize)
	return nil
}

// computePriPubPair computes a private/public DH pair
func (k *keyMgr) computePriPubPair() error {
	var err error
	k.group, err = dhkx.GetGroup(0)
	if err != nil { return err }
	k.priKey, err = k.group.GeneratePrivateKey(nil)
	if err != nil { return err }
	k.pubKey = k.priKey.Bytes()
	return nil
}

// getPubKey mediates the access to the singleton pubKey (and priKey in turn)
func (k *keyMgr) getPubKey() ([]byte, error) {
	k.pubKeyCheckMutex.Lock()
	defer k.pubKeyCheckMutex.Unlock()
	if len(k.pubKey) == 0 {
		if err := k.computePriPubPair(); err != nil { return nil, err }
	}
	return k.pubKey, nil
}

// getAuthdPubKey returns an authenticated pubKey using getCMAC keyed with authKey
func (k *keyMgr) getAuthdPubKey(authKey []byte) ([]byte, []byte, error){
	pubKey, err := k.getPubKey()
	if err != nil { return nil, nil, err }
	pubTag, err := getCMAC(pubKey, authKey)
	if err != nil { return nil, nil, err }
	return pubKey, pubTag, nil
}

// verifyRemotePubKey verifies that tag is the CMAC (keyed with authKey) of key
func (k *keyMgr) verifyRemotePubKey(tag []byte, key []byte, authKey []byte) (bool, error) {
	// Check remote key authenticity
	c, err := aes.NewCipher(authKey)
	if err != nil { return false, err }
	return cmac.Verify(tag, key, c, len(authKey)), nil
}

// computeSharedKey completes the DH key exchange and stores the results in the keyMgr
func (k *keyMgr) computeSharedKey(remotePubKey []byte) error {
	key, err := k.group.ComputeKey(dhkx.NewPublicKey(remotePubKey), k.priKey)
	if err != nil { return err }
	k.key = key.Bytes()
	return nil
}

