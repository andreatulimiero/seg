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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"net"
	"time"
)

var _ snet.Path = (*partialHiddenPath)(nil)

// partialHiddenPath is a path object with incomplete metadata. It is used as a
// temporary solution where a full path cannot be reconstituted from other
// objects, notably snet.UDPAddr and snet.SVCAddr.
type partialHiddenPath struct {
	spath   *spath.Path
	ifaces  []sciond.PathInterface
	overlay *net.UDPAddr
	dst     addr.IA
}

func newPartialHiddenPath(p *combinator.Path, nextHop *net.UDPAddr, dst addr.IA) (*partialHiddenPath, error) {
	x := &bytes.Buffer{}
	_, err := p.WriteTo(x)
	if err != nil {
		// In-memory write should never fail
		panic(err)
	}
	sp := spath.New(x.Bytes())
	if err := sp.InitOffsets(); err != nil {
		return nil, err
	}
	return &partialHiddenPath{
		spath:   sp,
		ifaces:  p.Interfaces,
		overlay: nextHop,
		dst:     dst,
	}, nil
}

func copyUDP(udp *net.UDPAddr) *net.UDPAddr {
	if udp == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(udp.IP[:0:0], udp.IP...),
		Port: udp.Port,
	}
}

func (p *partialHiddenPath) Fingerprint() snet.PathFingerprint {
	return ""
}

func (p *partialHiddenPath) OverlayNextHop() *net.UDPAddr {
	return p.overlay
}

func (p *partialHiddenPath) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *partialHiddenPath) Interfaces() []snet.PathInterface {
	if p.ifaces == nil {
		return nil
	}
	intfs := make([]snet.PathInterface, 0, len(p.ifaces))
	for _, intf := range p.ifaces {
		intfs = append(intfs, intf)
	}
	return intfs
}

func (p *partialHiddenPath) Destination() addr.IA {
	return p.dst
}

func (p *partialHiddenPath) MTU() uint16 {
	return 0
}

func (p *partialHiddenPath) Expiry() time.Time {
	return time.Time{}
}

func (p *partialHiddenPath) Copy() snet.Path {
	if p == nil {
		return nil
	}
	return &partialHiddenPath{
		spath:   p.spath.Copy(),
		overlay: copyUDP(p.overlay),
		dst:     p.dst,
	}
}
