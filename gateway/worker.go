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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	chanLength = 1500
)

type worker struct {
	gateway *Gateway
	pktsChannel chan []byte
	pktsPool *memPool
	adapter Adapter
}

func newWorker(adapter Adapter, gateway *Gateway) *worker {
	w := &worker{
		gateway: gateway,
		adapter: adapter,
		pktsChannel: make(chan []byte, chanLength),
		//pktsPool:sync.Pool{
		//	New: func() interface{} {
		//		return make([]byte, common.MaxMTU)
		//	},
		//},
		pktsPool: newMemPool(common.MaxMTU, chanLength),
	}
	return w
}

type ingressWorker struct {
	worker
}

func newIngressWorker(adapter Adapter, gateway *Gateway) *ingressWorker {
	return &ingressWorker{*newWorker(adapter, gateway)}
}

func (w *ingressWorker) Run() {
	log.Debug("Starting ingress worker", "adapter", w.adapter)
	for buf := range w.pktsChannel {
		w.adapter.ProcessIngressPkt(buf)
		if useWorkerMemPool {
			w.pktsPool.put(buf[:cap(buf)])
		}
	}
}

type egressWorker struct {
	worker
}

func newEgressWorker(adapter Adapter, gateway *Gateway) *egressWorker {
	return &egressWorker{*newWorker(adapter, gateway)}
}

func (w *egressWorker) Run() {
	log.Debug("Starting egress worker", "adapter", w.adapter)
	for buf := range w.pktsChannel {
		w.adapter.ProcessEgressPkt(buf, w.gateway.getPeerWriter)
		if useWorkerMemPool {
			w.pktsPool.put(buf[:cap(buf)])
		}
	}
}
