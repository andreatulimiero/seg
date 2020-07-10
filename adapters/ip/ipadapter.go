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
	"encoding/gob"
	"fmt"
	"github.com/andreatulimiero/seg/gateway"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"
	"io"
	"net"
)

var _ gateway.Adapter = (*IPAdapter)(nil)

const (
	defaultMTU 	  	= 1200
	defaultTxQlen 	= 1000
	defaultTunName	= "tun0"
	ip4Ver    = 0x4
	ip4DstOff = 16
)

func init() {
	gob.Register(&ConfMsg{})
}

type ConfMsg struct {
	//MACs         []laneca.Device
	//FlowPolicies []laneca.FlowPolicyConf
	Net          net.IPNet
}

type Conf struct {
	Subnet  *YIPNet
	Addr    *YIP
	TunName string `yaml:"tunName"`
	MTU     int
	TxQlen  int
}

type netToClient struct {
	net *net.IPNet
	IA string
}

type IPAdapter struct {
	conf    Conf
	tunLink netlink.Link
	tunIO   io.ReadWriteCloser
	router  *Router
}

func newIPAdapter(conf Conf) (*IPAdapter, error) {
	a := &IPAdapter{conf: conf}
	a.router = newRouter(a)
	var err error
	a.tunLink, a.tunIO, err = getTun(conf.MTU, conf.TxQlen, *conf.Addr.IP, conf.TunName)
	if err != nil { return nil, err }
	return a, nil
}

// getTun creates and sets up a Tun interface
func getTun(MTU int, TxQlen int, ipAddr net.IP, tunName string) (netlink.Link, *water.Interface, error) {
	tun, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: tunName}})
	if err != nil {
		return nil, nil, err
	}
	link, err := netlink.LinkByName(tun.Name())
	if err != nil {
		err := tun.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, nil, err
	}
	err = netlink.LinkSetMTU(link, MTU)
	if err != nil {
		return nil, nil, err
	}
	err = netlink.LinkSetTxQLen(link, TxQlen)
	if err != nil {
		return nil, nil, err
	}
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP: ipAddr,
			Mask: net.IPv4Mask(0xFF, 0xFF, 0xFF, 0xFF)}})
	if err != nil {
		return nil, nil, err
	}
	return link, tun, nil
}

func getDestIP(buf []byte) (net.IP, error) {
	ver := buf[0] >> 4
	switch ver {
	case ip4Ver:
		return buf[ip4DstOff : ip4DstOff+net.IPv4len], nil
	default:
		return nil, common.NewBasicError("Unsupported IP protocol version in egress packet", nil,
			"type", ver)
	}
}

// NewIPAdapter returns a new IPAdapter
func NewIPAdapter(confBuf []byte) (*IPAdapter, error) {
	conf := Conf{
		MTU:     defaultMTU,
		TxQlen:  defaultTxQlen,
		TunName: defaultTunName,
	}
	err := yaml.UnmarshalStrict(confBuf, &conf)
	if err != nil {
		return nil, err
	}
	log.Info("IPAdapter configuration", "conf", conf)
	return newIPAdapter(conf)
}

func (adapter *IPAdapter) HandshakeComplete(peer gateway.PeerWriter) {
	msg := ConfMsg{
		//MACs:         Cfg.LaNeCa.MACs,
		//FlowPolicies: Cfg.LaNeCa.Policies.Flow,
		Net:          *adapter.conf.Subnet.IPNet}
	log.Debug("Sending conf to remote gateway")
	err := gateway.WriteMsg(msg, peer.CtrlWriter())
	if err != nil {
		log.Error("Error sending conf", "err", err)
	}
}

func (adapter *IPAdapter) ProcessCtrlMsg(msg gateway.Message, remoteIA addr.IA) {
	switch reqMsg := msg.(type) {
	case *ConfMsg:
		log.Debug("Received IP conf", "msg", reqMsg)
			//for _, mac := range conf.MACs {
			//	log.Debug("Updating mac forwarding", "mac", mac, "remote", peer.remote.Address.IA)
			//	lanecaAdapter.MACsToGatewayClientMap[mac.String()] = peer
			//}
			//LoadFlowPolicies(conf.FlowPolicies)
		err := adapter.router.addNet(&reqMsg.Net, remoteIA.String())
		if err != nil {
			log.Error("Error adding routing", "net", reqMsg.Net, "remoteIA", remoteIA, "err", err)
		}
	default:
		log.Warn("Unknown message type received", "type", fmt.Sprintf("%T", msg))
	}
}

func (adapter *IPAdapter) ProcessIngressPkt(buf []byte) {
	n, err := adapter.tunIO.Write(buf)
	if err != nil {
		log.Error("Error writing ingress pkt to tun", "err", err)
	} else if n < len(buf) {
		log.Warn("Couldn't write ingress pkt in one go")
	}
}

func (adapter *IPAdapter) ProcessEgressPkt(buf []byte, getPeerWriter func(string) (gateway.PeerWriter, error)) {
	dstIP, err := getDestIP(buf)
	if err != nil {
		log.Debug("Error getting destination IP", "err", err)
		return
	}
	//log.Debug("Forwarding pkt to dstIP", "dst", dstIP)
	remoteIA, err := adapter.router.Lookup(dstIP)
	if err != nil {
		log.Error("No remote IA found", "dst", dstIP)
		return
	}
	w, err := getPeerWriter(remoteIA)
	if err != nil {
		log.Error("Error getting writer", "remoteIA", remoteIA, "err", err)
	}
	n, err := w.DataWriter().Write(buf)
	switch err {
	case nil:
	case gateway.PeerIsMigratingError:
		log.Debug("Skipping writing", "err", err)
	default:
		log.Error("Error writing buffer to remote", "err", err)
	}
	if err != nil {
	} else if n < len(buf) {
		log.Warn("Couldn't write buf in one go")
	}
}

func (adapter *IPAdapter) Read(buf []byte) (int, error){
	return adapter.tunIO.Read(buf)
}

func (adapter *IPAdapter) String() string {
	return fmt.Sprintf("IP @ %s", adapter.tunLink.Attrs().Name)
}
