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
	"flag"
	"github.com/scionproto/scion/go/lib/sciond"
	"time"
)

const (
	useWorkerMemPool       = true
	handshakeRetryInterval = 1 * time.Second
	pathRefreshInterval    = 15 * time.Second
)

var (
	dispatcher     = flag.String("dispatcher", "", "Path to dispatcher socket")
	sciondAddr     = flag.String("sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	hiddenFailover = flag.Bool("hiddenFailover", false, "[TEST] force failover over hidden path")
)

type conf struct {
	// Address is the full address of the gateway, including the IP and Port at which it will listen for connections
	Address         YUDPAddr
	AdapterConfPath string `yaml:"adapterConfPath"`
	Remotes         []connConf
	Pathing         pathingConf
}
