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
	"github.com/scionproto/scion/go/lib/addr"
	"time"

	"github.com/JordiSubira/drkeymockup/drkey"
	"github.com/JordiSubira/drkeymockup/drkey/protocol"
	"github.com/JordiSubira/drkeymockup/mockupsciond"
)

type drkeyMgr struct {
	peer *peer
	metaClient, metaServer drkey.Lvl2Meta
}

func newDRKeyMgr(peer *peer) *drkeyMgr {
	return &drkeyMgr{
		peer: peer,
		metaClient: drkey.Lvl2Meta{
			KeyType:  drkey.Host2Host,
			Protocol: "piskes",
			SrcIA:    peer.gateway.localAddr().IA,
			DstIA:    peer.remoteAddr().IA,
			SrcHost:  addr.HostFromIP(peer.gateway.localAddr().Host.IP),
			DstHost:  addr.HostFromIP(peer.remoteAddr().Host.IP),
		},
		metaServer: drkey.Lvl2Meta{
			KeyType:  drkey.Host2Host,
			Protocol: "piskes",
			SrcIA:    peer.remoteAddr().IA,
			DstIA:    peer.gateway.localAddr().IA,
			SrcHost:  addr.HostFromIP(peer.remoteAddr().Host.IP),
			DstHost:  addr.HostFromIP(peer.gateway.localAddr().Host.IP),
		},
	}
}

func (m *drkeyMgr) clientHostKey() ([]byte, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	now := uint32(time.Now().Unix())
	// get L2 key: (slow path)
	key, err := mockupsciond.DRKeyGetLvl2Key(ctx, m.metaClient, now); if err != nil {
		return nil, err
	}
	return key.Key, nil
}

func (m *drkeyMgr) dsForServer() (*drkey.DelegationSecret, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	dsMeta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: m.metaServer.Protocol,
		SrcIA:    m.metaServer.SrcIA,
		DstIA:    m.metaServer.DstIA,
	}
	now := uint32(time.Now().Unix())
	lvl2Key, err := mockupsciond.DRKeyGetLvl2Key(ctx, dsMeta, now); if err != nil {
		return nil, err
	}
	return &drkey.DelegationSecret{
		Protocol: lvl2Key.Protocol,
		Epoch:    lvl2Key.Epoch,
		SrcIA:    lvl2Key.SrcIA,
		DstIA:    lvl2Key.DstIA,
		Key:      lvl2Key.Key,
	}, nil
}

func (m *drkeyMgr) hostKeyFromDS(ds *drkey.DelegationSecret) (*drkey.Lvl2Key, error) {
	piskes := (protocol.KnownDerivations["piskes"]).(protocol.DelegatedDerivation)
	derived, err := piskes.DeriveLvl2FromDS(m.metaServer, *ds); if err != nil {
		return nil, err
	}
	return &derived, nil
}

func (m *drkeyMgr) serverHostKey() ([]byte, error) {
	ds, err := m.dsForServer(); if err != nil {
		return nil, err
	}
	drkey, err := m.hostKeyFromDS(ds); if err != nil {
		return nil, err
	}
	return drkey.Key, nil
}
