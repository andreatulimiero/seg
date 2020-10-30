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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"net"
	"os"
	"strings"
)

func assert(cond bool, msg string) {
	if cond {
		return
	}
	panic(msg)
}

// LogFatal logs a critical message and exits with error code 1
func LogFatal(msg string, a ...interface{}) {
	fmt.Printf("Critical")
	log.Crit(msg, a...)
	os.Exit(1)
}

func getSCIONNetwork(dispatcher string, sciondAddr string, IA addr.IA) (sciond.Connector, *snet.SCIONNetwork, error) {
	ds := reliable.NewDispatcher(dispatcher)
	sciondConn, err := sciond.NewService(sciondAddr).Connect(context.Background())
	if err != nil {
		return nil, nil, err
	}
	network := snet.NewNetworkWithPR(IA, ds, &sciond.Querier{
		Connector: sciondConn,
		IA:        IA,
	}, &RevocationHandler{})
	return sciondConn, network, nil
}

func getConnLocalPort(conn *snet.Conn) int {
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func ifacesToString(ifaces []snet.PathInterface) string {
	if len(ifaces) == 0 {
		return ""
	}
	strs := []string{fmt.Sprintf("%s %d", ifaces[0].IA(), ifaces[0].ID())}
	for i := 1; i < len(ifaces)-1; i += 2 {
		strs = append(strs, fmt.Sprintf("%d %s %d", ifaces[i].ID(), ifaces[i].IA(), ifaces[i+1].ID()))
	}
	strs = append(strs, fmt.Sprintf("%d %s", ifaces[len(ifaces)-1].ID(), ifaces[len(ifaces)-1].IA()))
	return strings.Join(strs, ">")
}

// YIA is a proxy for addr.IA to implement a custom Unmarshaler
type YIA struct {
	*addr.IA
}

func (ia *YIA) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sIA string
	err := unmarshal(&sIA)
	if err != nil {
		return err
	}
	other, err := addr.IAFromString(sIA)
	if err != nil {
		return err
	}
	ia.IA = &other
	return nil
}

// YUDPAddr is a proxy for snet.UDPAddr to implement a custom Unmarshaler
type YUDPAddr struct {
	*snet.UDPAddr
}

func (addr *YUDPAddr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sAddr string
	err := unmarshal(&sAddr)
	if err != nil {
		return err
	}
	other, err := snet.ParseUDPAddr(sAddr)
	if err != nil {
		return err
	}
	addr.UDPAddr = other
	return nil
}
