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
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/andreatulimiero/spp/gateway"
	"github.com/andreatulimiero/spp/gateway/utils"
	"net"

	"github.com/mdlayher/ethernet"
	"github.com/scionproto/scion/go/lib/log"
)

// LaNeCa settings
const (
	LaNeCaMACSize = 16
	LaNeCaMACsNum = 1
	LaNeCaKeySize = 16
	LaNeCaKeysNum = LaNeCaMACsNum
)

// LaNeCa header
const (
	alignment            = 4
	sizeOfMACAddr        = 6
	sizeOfEthType        = 2
	sizeOfEthHdr         = 2*sizeOfMACAddr + sizeOfEthType
	sizeOfEthMaxPayload  = 1500
	sizeOfEthMinPayload  = 46
	sizeOfLaNeCaType     = 2
	sizeOfLaNeCaMACSize  = 1
	sizeOfLaNeCaMACsNum  = 1
	sizeOfLaNeCaMAC      = LaNeCaMACSize
	sizeOfLaNeCaHdrNoPad = sizeOfLaNeCaType + sizeOfLaNeCaMACsNum + sizeOfLaNeCaMACSize + sizeOfLaNeCaMAC*LaNeCaMACsNum
)

// LaNeCa dynamic sizes
var (
	sizeOfLaNeCaHdrPad,
	sizeOfLaNeCaHdr,
	sizeOfLaNeCaMaxPayload,
	sizeOfLaNeCaMinPayload int
)

func init() {
	rem := (sizeOfEthHdr + sizeOfLaNeCaHdrNoPad) % alignment
	if rem == 0 {
		sizeOfLaNeCaHdrPad = 0
	} else {
		sizeOfLaNeCaHdrPad = alignment - rem
	}
}

/*func sizeOfLaNeCaHdrPad() int {
	rem := (sizeOfEthHdr + sizeOfLaNeCaHdrNoPad) % alignment
	if rem == 0 {
		return 0
	}
	return alignment - rem
}

func sizeOfLaNeCaHdr() int { return sizeOfLaNeCaHdrNoPad + sizeOfLaNeCaHdrPad() }

func sizeOfLaNeCaMaxPayload() int { return sizeOfEthMaxPayload - sizeOfLaNeCaHdr() }

func sizeOfLaNeCaMinPayload() int { return sizeOfEthMinPayload - sizeOfLaNeCaHdr() }
*/

// LaNeCa message types
const (
	// LaNeCaTypeLaNeCaUpdate is the LaNeCaType for keys updates
	LaNeCaTypeLaNeCaUpdate = 0x8ecb
)

// LaNeCa key levels
const (
	LaNeCaKeyLevelRoot = iota
	LaNeCaKeyLevelRecv
	LaNeCaKeyLevelFlow
)

// Key derivation sizes
const (
	sizeOfKeyLevel              = 1
	recvKeyByteStringSize       = sizeOfMACAddr
	paddedRecvKeyByteStringSize = ((recvKeyByteStringSize + LaNeCaKeySize - 1) / LaNeCaKeySize) * LaNeCaKeySize
	flowKeyByteStringSize       = sizeOfMACAddr + sizeOfLaNeCaType
	paddedFlowKeyByteStringSize = ((flowKeyByteStringSize + LaNeCaKeySize - 1) / LaNeCaKeySize) * LaNeCaKeySize
)

var (
	// Dummy rootKey
	rootKey = []byte{0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64}
)

type LaNeCaPacket struct {
	Src, Dst net.HardwareAddr
	Type     uint16
	MACSize  uint8
	MACsNum  uint8
	MACs     [][]byte
	Payload  []byte
}

func (pkt *LaNeCaPacket) UnmarshalBinary(src, dst net.HardwareAddr, b []byte) error {
	// fmt.Printf("%s", hex.Dump(b))
	pkt.Src = src
	pkt.Dst = dst
	off := 0
	pkt.Type = binary.BigEndian.Uint16(b[off : off+sizeOfLaNeCaType])
	off += sizeOfLaNeCaType
	pkt.MACSize = b[off]
	off += sizeOfLaNeCaMACSize
	if pkt.MACSize != LaNeCaMACSize {
		return fmt.Errorf("variable size of macs not supported, expected: %d, found: %d", LaNeCaMACSize, pkt.MACSize)
	}
	pkt.MACsNum = b[off]
	if pkt.MACsNum != LaNeCaMACsNum {
		return fmt.Errorf("variable number of macs not supported, expected: %d, found: %d", LaNeCaMACsNum, pkt.MACsNum)
	}
	off += sizeOfLaNeCaMACsNum + sizeOfLaNeCaHdrPad
	var i uint8
	for i = 0; i < pkt.MACsNum; i++ {
		pkt.MACs = append(pkt.MACs, b[off:off+sizeOfLaNeCaMAC])
		off += sizeOfLaNeCaMAC
	}
	pkt.Payload = b[off:]
	return nil
}

// TODO: Cache previously computed flow keys for data plane
func (pkt *LaNeCaPacket) TagValid() ([]bool, error) {
	/* TODO
	log.Debug("Checking LaNeCa packet ...")
	checkRes := make([]bool, len(pkt.MACs))
	for i := range pkt.MACs {
		recvKey, err := getRecvKey(rootKey, pkt.Dst)
		if err != nil {
			return nil, err
		}
		flowKey, err := getFlowKey(recvKey, pkt.Src, pkt.Type)
		if err != nil {
			return nil, err
		}
		mac, err := getCMAC(pkt.Payload, flowKey)
		if err != nil {
			return nil, err
		}
		checkRes[i] = bytes.Equal(mac[:LaNeCaMACSize], pkt.MACs[i])
	}
	return checkRes, nil
	*/
	return nil, nil
}

type LaNeCaKeysUpdateReq struct {
	level uint8
}

type LaNeCaRecvKeysReq struct {
	LaNeCaKeysUpdateReq
	dst net.HardwareAddr
}

type LaNeCaFlowKeysReq struct {
	LaNeCaRecvKeysReq
	src   net.HardwareAddr
	type_ uint16
}

func (recvkr *LaNeCaRecvKeysReq) UnmarshalBinary(b []byte) error {
	log.Debug("Unmarshalling recv keys update")
	off := 0
	recvkr.level = b[off]
	off += sizeOfKeyLevel
	recvkr.dst = b[off : off+sizeOfMACAddr]
	return nil
}

func (recvkr *LaNeCaRecvKeysReq) GetResponse() ([]byte, error) {
	resSize := sizeOfKeyLevel + LaNeCaKeySize*LaNeCaKeysNum + sizeOfMACAddr
	res := make([]byte, resSize)
	off := 0
	res[off] = LaNeCaKeyLevelRecv
	off += sizeOfKeyLevel
	for i := 0; i < LaNeCaKeysNum; i++ {
		recvKey, err := getRecvKey(rootKey, recvkr.dst)
		if err != nil {
			return nil, err
		}
		copy(res[off:off+LaNeCaKeySize], recvKey)
		off += LaNeCaKeySize
	}
	copy(res[off:], recvkr.dst)
	return res, nil
}

func (flowkr *LaNeCaFlowKeysReq) UnmarshalBinary(b []byte) error {
	log.Debug("Unmarshalling flow keys update")
	off := 0
	flowkr.level = b[off]
	off += sizeOfKeyLevel
	flowkr.dst = b[off : off+sizeOfMACAddr]
	off += sizeOfMACAddr
	flowkr.src = b[off : off+sizeOfMACAddr]
	off += sizeOfMACAddr
	flowkr.type_ = binary.BigEndian.Uint16(b[off : off+sizeOfLaNeCaType])
	off += sizeOfLaNeCaType
	return nil
}

func (flowkr *LaNeCaFlowKeysReq) GetResponse() ([]byte, error) {
	resSize := sizeOfKeyLevel + LaNeCaKeySize*LaNeCaKeysNum + 2*sizeOfMACAddr + sizeOfLaNeCaType
	res := make([]byte, resSize)
	off := 0
	res[off] = LaNeCaKeyLevelFlow
	off += sizeOfKeyLevel
	for i := 0; i < LaNeCaKeysNum; i++ {
		recvKey, err := getRecvKey(rootKey, flowkr.dst)
		if err != nil {
			return nil, err
		}
		flowKey, err := getFlowKey(recvKey, flowkr.src, flowkr.type_)
		if err != nil {
			return nil, err
		}
		copy(res[off:off+LaNeCaKeySize], flowKey)
		off += LaNeCaKeySize
	}
	copy(res[off:], flowkr.dst)
	off += sizeOfMACAddr
	copy(res[off:], flowkr.src)
	off += sizeOfMACAddr
	binary.BigEndian.PutUint16(res[off:], flowkr.type_)
	return res, nil
}

func getRecvKey(rootKey []byte, dst net.HardwareAddr) ([]byte, error) {
	buf := make([]byte, paddedRecvKeyByteStringSize)
	copy(buf, dst)
	return gateway.GetBufCBCMAC(buf, rootKey)
}

func getFlowKey(recvKey []byte, src net.HardwareAddr, _type uint16) ([]byte, error) {
	buf := make([]byte, paddedFlowKeyByteStringSize)
	copy(buf, src)
	binary.BigEndian.PutUint16(buf[len(src):], _type)
	return gateway.GetBufCBCMAC(buf, recvKey)
}

func HandleKeyUpdateReq(src net.HardwareAddr, b []byte) ([]byte, error) {
	// fmt.Printf(hex.Dump(b))
	off := 0
	level := b[off]
	off += sizeOfKeyLevel
	switch level {
	case LaNeCaKeyLevelRoot:
		return nil, fmt.Errorf("TBD")
	case LaNeCaKeyLevelRecv:
		var recvkr LaNeCaRecvKeysReq
		err := recvkr.UnmarshalBinary(b)
		if err != nil {
			return nil, err
		}
		log.Info("Recv key request", "flowDst", recvkr.dst)
		return recvkr.GetResponse()
	case LaNeCaKeyLevelFlow:
		var flowkr LaNeCaFlowKeysReq
		err := flowkr.UnmarshalBinary(b)
		if err != nil {
			return nil, err
		}
		ok := PolicyCheck(flowkr.src, flowkr.dst, flowkr.type_)
		if !ok {
			return nil, NewPolicyNotAllowedError(flowkr.src, flowkr.dst, flowkr.type_)
		}
		log.Info("Flow key request", "flowDst", flowkr.dst, "flowSrc", flowkr.src, "type", fmt.Sprintf("%#x", flowkr.type_))
		return flowkr.GetResponse()
	default:
		return nil, fmt.Errorf("unknown key level: %d", level)
	}
}

func GetLaNeCaPacket(src, dst net.HardwareAddr, lanecaType uint16, pld []byte) ([]byte, error) {
	pktSize := sizeOfLaNeCaType + sizeOfLaNeCaMACSize + sizeOfLaNeCaMACsNum + sizeOfLaNeCaHdrPad + LaNeCaMACSize*LaNeCaMACsNum + len(pld)
	if pktSize > sizeOfLaNeCaMaxPayload {
		LogFatal("Packet Too big")
	}
	pkt := bytes.Repeat([]byte{0x0}, pktSize)
	off := 0
	binary.BigEndian.PutUint16(pkt[off:], lanecaType)
	off += sizeOfLaNeCaType
	pkt[off] = uint8(LaNeCaMACSize)
	off += sizeOfLaNeCaMACSize
	pkt[off] = uint8(LaNeCaMACsNum)
	off += sizeOfLaNeCaMACsNum + sizeOfLaNeCaHdrPad
	for i := 0; i < LaNeCaMACsNum; i++ {
		recvKey, err := getRecvKey(rootKey, dst)
		if err != nil {
			return nil, err
		}
		flowKey, err := getFlowKey(recvKey, src, lanecaType)
		if err != nil {
			return nil, err
		}
		pad := utils.Max(0, sizeOfLaNeCaMinPayload-len(pld))
		paddedPld := append(pld, bytes.Repeat([]byte{0x0}, pad)...)
		mac, err := gateway.GetBufCMAC(paddedPld, flowKey)
		if err != nil {
			return nil, err
		}
		copy(pkt[off:], mac[:sizeOfLaNeCaMAC])
		off += sizeOfLaNeCaMAC
	}
	copy(pkt[off:], pld)
	frame := &ethernet.Frame{
		Source:      src,
		Destination: dst,
		EtherType:   0x8eca,
		Payload:     pkt,
	}
	frameBuf, err := frame.MarshalBinary()
	if err != nil {
		LogFatal("Error marshalling response", "err", err)
	}
	return frameBuf, nil
}
