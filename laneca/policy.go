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
	"net"

	"github.com/mdlayher/ethernet"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	// Policy type
	clientServerType = "client/server"
	peerType         = "peer"
)

var (
	policies         = make(map[string]bool)
	protoToEtherType = map[string]ethernet.EtherType{
		"IP":  ethernet.EtherTypeIPv4,
		"ARP": ethernet.EtherTypeARP,
	}
)

type policyType string

type PolicyNotAllowedError struct {
	Src, Dst net.HardwareAddr
	Type     uint16
}

func NewPolicyNotAllowedError(src, dst net.HardwareAddr, type_ uint16) *PolicyNotAllowedError {
	return &PolicyNotAllowedError{Src: src, Dst: dst, Type: type_}
}

func (e *PolicyNotAllowedError) Error() string {
	return fmt.Sprintf("%s cannot communicate with %s over %s\n", e.Src.String(), e.Dst.String(), fmt.Sprintf("%#x", e.Type))
}

type RootPolicyConf struct {
	Rate    float32
	Classes [][]Device
}

type FlowPolicyConf struct {
	Mode      policyType
	Clients   []Device
	Servers   []Device
	Protocols []string
}

func LoadFlowPolicies(policyConf []FlowPolicyConf) {
	for _, p := range policyConf {
		switch p.Mode {
		case clientServerType:
			if len(p.Clients) == 0 || len(p.Servers) == 0 {
				log.Error("Invalid policy, client/server must have at least one client and one server")
				continue
			}
			for _, c := range p.Clients {
				cAddr := c.String()
				for _, s := range p.Servers {
					sAddr := s.String()
					for _, p := range p.Protocols {
						protoNum, found := protoToEtherType[p]
						if !found {
							log.Error("Unknown protocol")
						}
						policyId := fmt.Sprintf("%s,%s,%s", cAddr, sAddr, protoNum)
						policies[policyId] = true
					}
				}
			}
		case peerType:
			if len(p.Clients) == 0 {
				log.Error("Empty peer policy")
				continue
			}
			if len(p.Servers) > 0 {
				log.Error("All devices in a peer policy must be specified in the clients section")
				continue
			}
			for _, c := range p.Clients {
				cAddr := c.String()
				for _, s := range p.Clients {
					sAddr := s.String()
					if cAddr == sAddr {
						continue
					}
					for _, p := range p.Protocols {
						protoNum, found := protoToEtherType[p]
						if !found {
							log.Error("Unknown protocol")
						}
						policyId := fmt.Sprintf("%s,%s,%s", cAddr, sAddr, protoNum)
						policies[policyId] = true
					}
				}
			}
		default:
			log.Error("Unkown policy type")
		}
	}
	for p := range policies {
		log.Info("Allowed traffic", "policy", p)
	}
}

func PolicyCheck(src, dst net.HardwareAddr, type_ uint16) bool {
	ethType := ethernet.EtherType(type_)
	policyId := fmt.Sprintf("%s,%s,%s", src, dst, ethType)
	_, ok := policies[policyId]
	return ok
}
