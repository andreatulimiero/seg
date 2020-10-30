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
	"context"
	"fmt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"gopkg.in/yaml.v2"
)

type Gateway struct {
	conf          conf
	network       snet.Network
	sdConn        sciond.Connector
	asClientMap   map[string]*peer
	adapter       Adapter
	egressWorker  *egressWorker
	ingressWorker *ingressWorker
	pathDBPath    string
}

func newGateway(conf conf, pathDBPath string) (*Gateway, error) {
	gateway := &Gateway{
		conf:        conf,
		pathDBPath:  pathDBPath,
		asClientMap: make(map[string]*peer),
	}
	var err error
	gateway.sdConn, gateway.network, err = getSCIONNetwork(*dispatcher, *sciondAddr, gateway.conf.Address.IA)
	if err != nil {
		return nil, err
	}
	return gateway, nil
}

func (gateway *Gateway) startWorkers(adapter Adapter) {
	gateway.egressWorker = newEgressWorker(adapter, gateway)
	go gateway.egressWorker.Run()
	gateway.ingressWorker = newIngressWorker(adapter, gateway)
	go gateway.ingressWorker.Run()
}

func (gateway *Gateway) accept() {
	conn, err := gateway.network.Listen(context.Background(), "udp", gateway.localAcceptAddr().Host, addr.SvcNone)
	if err != nil {
		LogFatal("Unable to listen for incoming ctrl messages", "err", err)
	}
	log.Debug("Accepting peer connections", "addr", conn.LocalAddr())
	for {
		msg, raddr, err := ReadMsg(conn)
		if err != nil {
			log.Error("Error reading controler message", "err", err)
			continue
		}
		log.Trace("Received new control message", "type", fmt.Sprintf("%T", msg))
		switch reqMsg := msg.(type) {
		case *handshakeRequestMsg:
			peer, err := gateway.getPeer(raddr.IA.String())
			if err != nil {
				log.Error("Error retrieving peer", "raddr", raddr.IA)
				continue
			}
			go peer.handleHandshakeRequest(reqMsg)
		case *handshakeResponseMsg:
			peer, err := gateway.getPeer(raddr.IA.String())
			if err != nil {
				log.Error("Error retrieving peer", "raddr", raddr.IA)
				continue
			}
			go peer.handleHandshakeResponse(reqMsg)
		default:
			log.Warn("Unknown message type received from gateway", "type", fmt.Sprintf("%T", msg))
		}
	}
}

func (gateway *Gateway) listen() {
	buf := make([]byte, common.MaxMTU)
	for {
		n, err := gateway.adapter.Read(buf)
		if err != nil {
			log.Error("Error reading from ", "adapter", gateway.adapter, "err", err)
			continue
		}

		if useWorkerMemPool {
			freeBuf := gateway.egressWorker.pktsPool.get()
			if freeBuf == nil {
				log.Debug("Couldn't retrieve free buf")
				continue
			}
			gateway.ProcessEgressPkt(buf[:n])
			buf = freeBuf
		} else {
			gateway.ProcessEgressPkt(buf[:n])
			buf = make([]byte, common.MaxMTU)
		}
	}
}

func (gateway *Gateway) localAddr() *snet.UDPAddr {
	a := gateway.conf.Address.UDPAddr.Copy()
	a.Host.Port = 0
	return a
}

func (gateway *Gateway) localAcceptAddr() *snet.UDPAddr { return gateway.conf.Address.UDPAddr }

func (gateway *Gateway) getConnTo(remoteAddr *snet.UDPAddr) (*snet.Conn, error) {
	sdConn, network := gateway.sdConn, gateway.network
	localAddr := gateway.localAddr()
	paths, err := sdConn.Paths(context.Background(), remoteAddr.IA, localAddr.IA, sciond.PathReqFlags{Refresh: true})
	if err != nil {
		return nil, err
	}
	remoteAddr.Path = paths[0].Path()
	remoteAddr.NextHop = paths[0].OverlayNextHop()
	newConn, err := network.Dial(context.Background(), "udp", localAddr.Host, remoteAddr, addr.SvcNone)
	if err != nil {
		return nil, err
	}
	return newConn, nil
}

// NewGateway returns a new Gateway.
func NewGateway(confBuf []byte, pathDBPath string) (*Gateway, error) {
	conf := conf{Pathing: defaultPathingConf}
	err := yaml.UnmarshalStrict(confBuf, &conf)
	if err != nil {
		return nil, err
	}
	log.Info("Gateway configuration", "conf", conf)
	return newGateway(conf, pathDBPath)
}

func (gateway *Gateway) SetAdapter(adapter Adapter) {
	gateway.adapter = adapter
	gateway.startWorkers(adapter)
}

// Start the gateway by accepting incoming connection requests from other peers, connecting to other peers,
// and listening to incoming local traffic using the adapter
func (gateway *Gateway) Start() {
	go gateway.accept()
	// initialize peer connections with other gateways
	for _, remoteConf := range gateway.conf.Remotes {
		remoteIA := remoteConf.Address.IA.String()
		peer, err := newPeer(gateway, remoteConf, &gateway.conf.Pathing)
		if err != nil {
			log.Error("Error creating peer", "remoteConf", remoteIA)
			continue
		}
		gateway.asClientMap[remoteIA] = peer
		go peer.initHandshaking()
	}
	go gateway.listen()
}

// ProcessIngressPkt passes a packet received from a peer to an ingress worker
func (gateway *Gateway) ProcessIngressPkt(b []byte) {
	gateway.ingressWorker.pktsChannel <- b
}

// ProcessEgressPkt passes a packet received from an adapter to an egress worker
func (gateway *Gateway) ProcessEgressPkt(b []byte) {
	gateway.egressWorker.pktsChannel <- b
}

// GetAdapterConfPath returns the file path of the Adapter configuration
func (gateway *Gateway) GetAdapterConfPath() string { return gateway.conf.AdapterConfPath }

// getPeer returns a peer, if any, for a remote gateway identified by IA
func (gateway *Gateway) getPeer(IA string) (*peer, error) {
	peer, ok := gateway.asClientMap[IA]
	if !ok {
		return nil, fmt.Errorf("Unknown client", "addr", IA)
	}
	return peer, nil
}

// getPeerWriter is similar to getPeer but scopes the returned peer to a PeerWriter
func (gateway *Gateway) getPeerWriter(IA string) (PeerWriter, error) {
	return gateway.getPeer(IA)
}

// WriteMsgOneOff writes a messages like WriteMsg but uses an ephemeral connection
func (gateway *Gateway) WriteMsgOneOff(msg Message, remoteAddr *snet.UDPAddr) error {
	c, err := gateway.getConnTo(remoteAddr)
	if err != nil {
		return err
	}
	return WriteMsg(msg, c)
}
