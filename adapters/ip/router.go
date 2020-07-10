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

package ipadapter

import (
	"fmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/vishvananda/netlink"
	"net"
)

type Router struct {
	adapter *IPAdapter
	netToClientList []netToClient
}

func newRouter(adapter *IPAdapter) *Router {
	return &Router{adapter: adapter}
}

func (r *Router) Lookup(addr net.IP) (string, error) {
	for _, nToC := range r.netToClientList {
		if nToC.net.Contains(addr) {
			return nToC.IA, nil
		}
	}
	return "", fmt.Errorf("client not found for %s", addr)
}

func (r *Router) addNet(dst *net.IPNet, IA string) error {
	// TODO: Check for duplicates
	r.netToClientList = append(r.netToClientList, netToClient{dst, IA})
	route := &netlink.Route{
		LinkIndex: r.adapter.tunLink.Attrs().Index,
		Dst:       dst,
	}
	log.Info("Adding route to tun", "net", route.Dst)
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}
	return nil
}

