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
	"github.com/scionproto/scion/go/lib/snet"
	"io"
	"net"
	"sync"
	"time"
)

type connConf struct {
	Address        YUDPAddr
	Description    string
	RendezvousAddr *YIA `yaml:"rendezvousAddr"`
}

// peer keeps track of the connection with another Gateway
type peer struct {
	gateway  *Gateway
	remote   connConf
	pathMgr  *pathMgr
	keyMgr   *keyMgr
	drkeyMgr *drkeyMgr
	// Egress connections
	egressCtrlEConn, egressDataEConn *eConn
	remoteCtrlPort, remoteDataPort   int
	// Ingress connections
	ingressCtrlConn, ingressDataConn *eConn
	// Handshaking
	handshakeRequestHandlerMutex sync.Mutex
	handshakeCompletionMutex     sync.Mutex
	cryptoHandshakeComplete      bool
	checkHandshakeComplete       bool
	handshakeCompleted           bool
}

type PeerWriter interface {
	CtrlWriter() io.Writer
	DataWriter() io.Writer
}

func (peer *peer) CtrlWriter() io.Writer {
	return peer.egressCtrlEConn
}

func (peer *peer) DataWriter() io.Writer {
	return peer.egressDataEConn
}

func newPeer(gateway *Gateway, remoteConf connConf, pathingConf *pathingConf) (*peer, error) {
	peer := &peer{
		gateway:                 gateway,
		remote:                  remoteConf,
		cryptoHandshakeComplete: false,
		checkHandshakeComplete:  false,
		handshakeCompleted:      false,
	}
	peer.pathMgr = newPathMgr(pathingConf, peer)
	peer.keyMgr = newKeyMgr(peer)
	peer.drkeyMgr = newDRKeyMgr(peer)

	err := peer.startIngressCtrlHandler()
	if err != nil {
		return nil, err
	}
	err = peer.startIngressDataHandler()
	if err != nil {
		return nil, err
	}

	return peer, err
}

func (peer *peer) startIngressCtrlHandler() error {
	var err error
	network := peer.gateway.network
	listenAddr := &net.UDPAddr{IP: peer.gateway.localAddr().Host.IP}
	conn, err := network.Listen(context.Background(), "udp", listenAddr, addr.SvcNone)
	if err != nil {
		return err
	}
	econn := newEConn(conn, peer)
	log.Debug("Listening for ctrl messages", "addr", econn.conn.LocalAddr())
	go func() {
		for {
			msg, raddr, err := ReadMsg(econn)
			if err != nil {
				log.Error("Error reading controller message", "err", err)
				continue
			}
			if !raddr.IA.Equal(peer.remote.Address.IA) {
				log.Warn("Received messaged from unexpected AS", "expected", peer.remote.Address.IA, "received", raddr.IA)
				continue
			}
			log.Trace("Received new control message", "type", fmt.Sprintf("%T", msg))
			switch reqMsg := msg.(type) {
			case *keepAliveMsg:
				peer.pathMgr.handleKeepAliveRequest(reqMsg)
			case *hiddenPathRequestMsg:
				if peer.remote.RendezvousAddr == nil {
					log.Warn("Ignoring hidden path request, rendezvous not set")
					continue
				}
				err := peer.pathMgr.handleHiddenPathRequest(reqMsg)
				if err != nil {
					log.Error("Error handling hidden path establishment request")
				}
			default:
				peer.gateway.adapter.ProcessCtrlMsg(msg, raddr.IA)
			}
		}
	}()
	peer.ingressCtrlConn = econn
	return nil
}

func (peer *peer) startIngressDataHandler() error {
	var err error
	network := peer.gateway.network
	listenAddr := &net.UDPAddr{IP: peer.gateway.localAddr().Host.IP}
	conn, err := network.Listen(context.Background(), "udp", listenAddr, addr.SvcNone)
	if err != nil {
		return err
	}
	econn := newEConn(conn, peer)
	log.Debug("Listening for incoming data", "addr", econn.conn.LocalAddr())
	go func() {
		buf := make([]byte, common.MaxMTU)
		for {
			n, _, err := econn.ReadFrom(buf)
			if err != nil {
				log.Error("Unable to read from network", "err", err)
				continue
			}

			freeBuf := peer.gateway.ingressWorker.pktsPool.get()
			if freeBuf == nil {
				log.Debug("Couldn't retrieve free buf")
				log.Error("Skipped ingress pkt")
				continue
			}
			peer.gateway.ProcessIngressPkt(buf[:n])
			buf = freeBuf
		}
	}()
	peer.ingressDataConn = econn
	return nil
}

// initHandshaking initiates a handshake process with a remote peer until it succeeds
func (peer *peer) initHandshaking() {
	log.Debug("Initiating handshake with", "addr", peer.remoteAddr())
	hostKey, err := peer.drkeyMgr.clientHostKey()
	if err != nil {
		log.Error("Error retrieving DRKey", "err", err)
		return
	}
	pubKey, pubTag, err := peer.keyMgr.getAuthdPubKey(hostKey)
	if err != nil {
		log.Error("Error getting authenticated public key", "err", err)
	}
	reqMsg := &handshakeRequestMsg{PubKey: pubKey,
		PubKeyTag: pubTag,
		CtrlPort:  getConnLocalPort(peer.ingressCtrlConn.conn),
		DataPort:  getConnLocalPort(peer.ingressDataConn.conn)}
	for !peer.handshakeCompleted {
		err = peer.gateway.WriteMsgOneOff(reqMsg, peer.remoteAddr())
		if err != nil {
			log.Error("Error sending handshake request", "err", err)
			return
		}
		log.Trace("Sent handshake request", "remote", peer.remoteAddr())
		time.Sleep(handshakeRetryInterval)
	}
}

// handleHandshakeRequest sets up connections with the other peer
func (peer *peer) handleHandshakeRequest(reqMsg *handshakeRequestMsg) {
	peer.handshakeRequestHandlerMutex.Lock()
	defer peer.handshakeRequestHandlerMutex.Unlock()
	log.Debug("Handling handshake request", "remote", peer.remoteAddr())
	if peer.cryptoHandshakeComplete {
		log.Warn("Ignoring handshake request, already completed")
		return
	}

	hostKey, err := peer.drkeyMgr.serverHostKey()
	if err != nil {
		log.Error("Error retrieving server host key", "err", err)
		return
	}
	tagMatch, err := peer.keyMgr.verifyRemotePubKey(reqMsg.PubKeyTag, reqMsg.PubKey, hostKey)
	if err != nil {
		log.Error("Error checking remote public key", "err", err)
	} else if !tagMatch {
		log.Error("Received public key authentication tag is not as expected")
	}

	// Setup egress connections
	peer.remoteCtrlPort, peer.remoteDataPort = reqMsg.CtrlPort, reqMsg.DataPort
	// manually update paths to setup initial connection
	err = peer.pathMgr.updatePathsToRemote()
	if err != nil {
		log.Error("Error updating paths to remote", "err", err)
		return
	}
	err = peer.setupEgressConnections()
	if err != nil {
		log.Error("Error setting up egress connections")
		return
	}

	// Setup data plane crypto
	err = peer.keyMgr.initDataCrypto(reqMsg.PubKey)
	if err != nil {
		log.Error("Error computing shared key", "err", err)
		return
	}
	peer.cryptoHandshakeComplete = true

	// Send ACK to remote gateway to check everything was successful
	err = peer.gateway.WriteMsgOneOff(handshakeResponseMsg{}, peer.remoteAddr())
	if err != nil {
		log.Error("Error sending handshake response msg", "err", err)
		return
	}
	peer.completeHandshake()
}

// handleHandshakeResponse confirms that the remote peer successfully initiated a connection with us
func (peer *peer) handleHandshakeResponse(resMsg *handshakeResponseMsg) {
	log.Debug("Handling handshake response", "remote", peer.remoteAddr())
	peer.checkHandshakeComplete = true
	peer.completeHandshake()
}

// completeHandshake completes handshake process (e.g., starting the pathMgr)
func (peer *peer) completeHandshake() {
	peer.handshakeCompletionMutex.Lock()
	defer peer.handshakeCompletionMutex.Unlock()
	if peer.handshakeCompleted {
		// Handshake already completed, no need to do anything
		assert(peer.cryptoHandshakeComplete && peer.handshakeCompleted, "")
		return
	}
	if !peer.cryptoHandshakeComplete || !peer.checkHandshakeComplete {
		// Handshake not complete yet, missing other part
		return
	}
	log.Info("Completed handshake", "remote", peer.remote.Address.IA)
	peer.pathMgr.start()
	go peer.gateway.adapter.HandshakeComplete(peer)
	peer.handshakeCompleted = true
}

func (peer *peer) getNewEConn(remoteIA addr.IA, remoteHost *net.UDPAddr, path snet.Path) (*eConn, error) {
	remoteAddr := &snet.UDPAddr{IA: remoteIA, Host: remoteHost}
	remoteAddr.Path = path.Path()
	remoteAddr.NextHop = path.OverlayNextHop()
	conn, err := peer.gateway.network.Dial(context.Background(), "udp", peer.gateway.localAddr().Host, remoteAddr, addr.SvcNone)
	if err != nil {
		return nil, err
	}
	return newEConn(conn, peer), nil
}

// setupEgressConnections sets up new egressConnections (ctrl and data) toward the remote peer using pathMgr's currPath
func (peer *peer) setupEgressConnections() error {
	var err error
	remoteAddr, remoteCtrlPort, remoteDataPort := peer.remoteAddr(), peer.remoteCtrlPort, peer.remoteDataPort
	path := peer.pathMgr.getCurrPath()

	remoteCtrlHost := &net.UDPAddr{IP: remoteAddr.Host.IP, Port: remoteCtrlPort}
	peer.egressCtrlEConn, err = peer.getNewEConn(remoteAddr.IA, remoteCtrlHost, path)
	if err != nil {
		return err
	}
	log.Info("Ctrl", "path", ifacesToString(path.Interfaces()))

	remoteDataHost := &net.UDPAddr{IP: remoteAddr.Host.IP, Port: remoteDataPort}
	peer.egressDataEConn, err = peer.getNewEConn(remoteAddr.IA, remoteDataHost, path)
	if err != nil {
		return err
	}
	log.Info("Data", "path", ifacesToString(path.Interfaces()))

	//go connFailHandler(client, peer.DataConn.conn)
	//go connFailHandler(client, peer.CtrlConn)
	return nil
}

func (peer *peer) remoteAddr() *snet.UDPAddr { return peer.remote.Address.UDPAddr }

func (peer *peer) String() string {
	return fmt.Sprintf("peer with %s", peer.remote.Address.IA)
}

func (peer *peer) WriteMsg(msg Message) error {
	return WriteMsg(msg, peer.egressCtrlEConn)
}
