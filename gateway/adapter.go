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
	"github.com/scionproto/scion/go/lib/addr"
)

type Adapter interface {
	// ProcessCtrlMsg allows the adapter to receive ctrl messages (see Message)
	ProcessCtrlMsg(Message, addr.IA)
	// HandshakeComplete informs the Adapter of the completion of a setup with a remote gateway
	HandshakeComplete(PeerWriter)
	// Read shall provide a method to read packets of interest from the local network
	Read([]byte) (int, error)
	// ProcessIngressPkt shall processing packets coming from remote gateways and dispatch them to the local network
	ProcessIngressPkt([]byte)
	// ProcessEgressPkt shall process packets coming from the local network and dispatch them to remote gateways
	ProcessEgressPkt([]byte, func(string) (PeerWriter, error))
}
