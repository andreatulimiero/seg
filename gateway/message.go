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
	"encoding/gob"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"io"
)

func init() {
	gob.Register(&keepAliveMsg{})
	gob.Register(&handshakeRequestMsg{})
	gob.Register(&handshakeResponseMsg{})
	gob.Register(&hiddenPathRequestMsg{})
}

type Message interface{}

type keepAliveMsg struct{}

type handshakeRequestMsg struct {
	PubKey    []byte
	PubKeyTag []byte
	CtrlPort 	int
	DataPort 	int
}

type handshakeResponseMsg struct {}

type hiddenPathRequestMsg struct {
	PathSegment seg.PathSegment
}

func writeMsg(msg Message, writer io.Writer) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(&msg)
	if err != nil {
		return err
	}
	n, err := writer.Write(buf.Bytes())
	if err != nil{
		return err
	} else if n < len(buf.Bytes()) {
		log.Error("Buffer too long", "required", len(buf.Bytes()), "sent", n)
	}
	return err
}

func WriteMsg(msg Message, writer io.Writer) error {
	return writeMsg(msg, writer)
}

func ReadMsg(reader readerFromAddr) (Message, *snet.UDPAddr, error) {
	var msg Message
	buf := make([]byte, common.MaxMTU)
	n, raddr, err := reader.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	err = gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(&msg)
	if err != nil {
		return nil, nil, err
	}
	return msg, raddr.(*snet.UDPAddr), nil
}

