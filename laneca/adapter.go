// For the sake of anonimity the license of this file has been stripped.
// The SHA256 of the original license is: 49912cd0c94c5722e6ca62b26cb1695ba2ab157dad87d9896c7b2ccdb1235c0a
// Copyright 2019-2021 xxx, xxx
// Author: xxx xxx <xxx>
//
// This file is part of LaNeCa
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package laneca

import (
	"fmt"
	"github.com/andreatulimiero/spp/gateway"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"io"
	"net"
)

var _ gateway.Adapter = (*Adapter)(nil)

type Device struct {
	net.HardwareAddr
}

func (dev *Device) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sAddr string
	err := unmarshal(&sAddr)
	if err != nil {
		return err
	}
	other, err := net.ParseMAC(sAddr)
	if err != nil {
		return err
	}
	dev.HardwareAddr = other
	return nil
}

type Policies struct {
	Root RootPolicyConf
	Flow []FlowPolicyConf
}

type AdapterConf struct {
	MACs      []Device
	Interface string
	Policies  Policies
}

type Adapter struct {
	iface       *net.Interface
	conn        *raw.Conn
	MACsToIAMap map[string]*addr.IA
}

func (a *Adapter) ProcessCtrlMsg(message gateway.Message, ia addr.IA) {
	panic("implement me")
}

func (a *Adapter) HandshakeComplete(peer *gateway.Peer) {
	panic("implement me")
}

func (a *Adapter) ProcessIngressPkt(buf []byte) {
	var (
		f   ethernet.Frame
		l   LaNeCaPacket
		err error
	)
	err = (&f).UnmarshalBinary(buf)
	if err != nil {
		log.Error("Error unmarshalling ethernet frame", "err", err)
		return
	}
	err = (&l).UnmarshalBinary(f.Source, f.Destination, f.Payload)
	if err != nil {
		log.Error("Error unmarshalling LaNeCa pkt", "err", err)
		return
	}
	checkRes, err := l.TagValid()
	if err != nil {
		log.Error("Error checking tag validity", "err", err)
	}
	authorized := true
	for i := range checkRes {
		if checkRes[i] {
			log.Info("TAG_OK", "idx", i)
		} else {
			log.Warn("TAG_ERR", "idx", i)
			authorized = false
		}
	}
	if !authorized {
		log.Error("Unauthorized packet")
		return
	}

	log.Debug("Dispatching packet", "src", f.Source, "dst", f.Destination)
	n, err := a.conn.WriteTo(buf, &raw.Addr{HardwareAddr: f.Destination})
	if err != nil {
		log.Error("Error writing ingress LaNeCa pkt")
	} else if n < len(buf) {
		log.Warn("Couldn't write ingress pkt in one go")
	}
}

func (a *Adapter) Read(buf []byte) (int, error) {
	n, _, err := a.conn.ReadFrom(buf)
	return n, err
}

func (a *Adapter) ProcessEgressPkt(buf []byte, lookupWriter func(string) (io.Writer, error)) {
	var (
		f   ethernet.Frame
		l   LaNeCaPacket
		err error
	)
	err = (&f).UnmarshalBinary(buf)
	if err != nil {
		log.Error("Error unmarshalling ethernet frame", "err", err)
	}
	err = (&l).UnmarshalBinary(f.Source, f.Destination, f.Payload)
	if err != nil {
		log.Error("Error unmarshalling LaNeCa pkt", "err", err)
	}
	checkRes, err := l.TagValid()
	if err != nil {
		log.Error("error checking tag validity", "err", err)
	}
	authorized := true
	for i := range checkRes {
		if checkRes[i] {
			log.Info("TAG_OK", "idx", i)
		} else {
			log.Warn("TAG_ERR", "idx", i)
			authorized = false
		}
	}
	if !authorized {
		log.Warn("Unauthorized packet")
	}

	switch l.Type {
	case LaNeCaTypeLaNeCaUpdate:
		res, err := HandleKeyUpdateReq(f.Source, l.Payload)
		switch err.(type) {
		case *PolicyNotAllowedError:
			fmt.Errorf("key request aborted: %s", err.Error())
		default:
			log.Error("Error handling key update", "err", err.Error())
		}
		pkt, err := GetLaNeCaPacket(f.Destination, f.Source, LaNeCaTypeLaNeCaUpdate, res)
		if err != nil {
			log.Error("Error getting LaNeCa packet", "err", err)
		}
		n, err := a.conn.WriteTo(pkt, &raw.Addr{HardwareAddr: f.Destination})
		if err != nil {
			log.Error("Error writing buffer to remote", "err", err)
		} else if n < len(buf) {
			log.Warn("Couldn't write buf in one go")
		}
	default:
		ia, ok := a.MACsToIAMap[f.Destination.String()]
		if !ok {
			log.Error("MAC not registered", "MAC", f.Destination.String())
		}
		w, err := lookupWriter(ia.String())
		if err != nil {
			log.Error("Error getting writer", "remoteIA", ia, "err", err)
		}
		n, err := w.Write(buf)
		if err != nil {
			log.Error("Error writing buffer to remote", "err", err)
		} else if n < len(buf) {
			log.Warn("Couldn't write buf in one go")
		}
	}
}

// NewLaNeCaAdapter returns a new instance of a LaNeCa adapter
func NewLaNeCaAdapter(conf AdapterConf) (*Adapter, error) {
	LoadFlowPolicies(conf.Policies.Flow)
	a := &Adapter{
		MACsToIAMap: make(map[string]*addr.IA),
	}
	iface, err := net.InterfaceByName(conf.Interface)
	if err != nil {
		return nil, err
	}
	c, err := raw.ListenPacket(iface, 0x8eca, nil)
	if err != nil {
		return nil, err
	}
	err = c.SetPromiscuous(true)
	if err != nil {
		return nil, err
	}
	a.iface = iface
	a.conn = c
	return a, nil
}
