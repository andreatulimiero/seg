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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
	"strings"
)

func (p partialHiddenPath) fmtInterfaces() []string {
	var hops []string
	if len(p.ifaces) == 0 {
		return hops
	}
	iface := p.ifaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", iface.IA(), iface.ID()))
	for i := 1; i < len(p.ifaces)-1; i += 2 {
		inIface := p.ifaces[i]
		outIface := p.ifaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIface.ID(), inIface.IA(), outIface.ID()))
	}
	iface = p.ifaces[len(p.ifaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", iface.ID(), iface.IA()))
	return hops
}

func (p partialHiddenPath) String() string {
	hops := p.fmtInterfaces()
	return fmt.Sprintf("Hops: [%s] MTU: %d, NextHop: %s",
		strings.Join(hops, ">"), p.MTU(), p.overlay)
}

func (m *pathMgr) handleHiddenPathRequest(reqMsg *hiddenPathRequestMsg) error {
	log.Debug("Received hidden path")
	paths, err := m.buildHiddenPaths(&reqMsg.PathSegment)
	if err != nil { return err }
	m.storeHiddenPaths(paths)
	return nil
}

func (m *pathMgr) buildHiddenPaths(remotePathSegment *seg.PathSegment) ([]snet.Path, error) {
	localPathSegment, err := m.getPathSegmentToRendezvous()
	if err != nil { return nil, err }
	paths, err := m.combineHiddenSegments(localPathSegment, remotePathSegment)
	if err != nil {
		return nil, fmt.Errorf("error combining hidden segments: %s", err)
	}
	return paths, nil
}

func (m *pathMgr) combineHiddenSegments(localPathSegment, remotePathSegment *seg.PathSegment) ([]snet.Path, error){
	var (
		ups, downs = []*seg.PathSegment{localPathSegment}, []*seg.PathSegment{remotePathSegment}
		localIA, remoteIA = m.peer.gateway.localAddr().IA, m.peer.remoteAddr().IA
	)
	log.Debug("Combining paths", "local", localPathSegment, "remote", remotePathSegment)
	paths := combinator.Combine(localIA, remoteIA, ups, []*seg.PathSegment{}, downs)
	var hiddenPaths []snet.Path
	// filter paths which do not contain the rendezvous -- this might be due to peering links with other peer
	for i, p := range paths {
		log.Debug("Combined hidden path", "idx", i, "p", p.Interfaces)
		foundRendezvous := false
		for _, iface := range p.Interfaces {
			if iface.IA().Equal(*m.peer.remote.RendezvousAddr.IA) {
				foundRendezvous = true
				break
			}
		}
		if foundRendezvous {
			hPath, err := newPartialHiddenPath(p, m.getOverlayNextHop(), m.peer.remoteAddr().IA); if err != nil {
				log.Error("Error creating partial hidden path", "err", err)
			}
			hiddenPaths = append(hiddenPaths, hPath)
		}
	}
	return hiddenPaths, nil
}

func (m *pathMgr) storeHiddenPaths(paths []snet.Path) {
	log.Info("Adding hidden path", "entries", paths)
	m.pathsUpdateMutex.Lock()
	defer m.pathsUpdateMutex.Unlock()
	m.hiddenPaths = append(m.hiddenPaths, paths...)
	m.hiddenPathsIdx = 0
}

func (m *pathMgr) getPathSegmentToRendezvous() (*seg.PathSegment, error) {
	remoteIA, rendezvousIA := m.peer.remote.Address.IA, m.peer.remote.RendezvousAddr
	pathSegment, err := getPathSegmentForAS(rendezvousIA.IA, &remoteIA, m.peer.gateway.pathDBPath)
	if err != nil {
		return nil, fmt.Errorf("error getting paths to rendezvous: addr = %s, err = %s", rendezvousIA, err)
	}
	return pathSegment, err
}

func (m *pathMgr) sendHiddenPath() error {
	localPathSegment, err := m.getPathSegmentToRendezvous()
	if err != nil { return err }
	hiddenPathMsg := &hiddenPathRequestMsg{PathSegment: *localPathSegment}
	log.Debug("Sending hidden paths ...")
	err = m.peer.WriteMsg(hiddenPathMsg)
	if err != nil {
		return fmt.Errorf("couldn't send hidden paths: %s", err)
	}
	return nil
}

// getPathSegmentForAS returns the first available up path to an AS
func getPathSegmentForAS(rendezvous, remote *addr.IA, dbPath string) (*seg.PathSegment, error) {
	db, err := sqlite.New(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ch, err := db.GetAll(context.Background())
	if err != nil {
		return nil, err
	}
	for res := range ch {
		if res.Err != nil {
			continue
		}
		foundRendezvous, foundRemote := false, false
		if res.Result.Type != proto.PathSegType_up { continue }
		var hops []addr.IA
		for _, as := range res.Result.Seg.ASEntries {
			hops = append(hops, as.IA())
			if rendezvous.Equal(as.IA()) {
				foundRendezvous = true
			}
			if remote.Equal(as.IA()) {
				foundRemote = true
			}
		}
		log.Trace("Filter", "hops", hops, "foundRendezvous", foundRendezvous, "foundRemote", foundRemote)
		if !foundRendezvous || foundRemote { continue }
		// TODO: Make some sort of selection out of the possible segments
		return res.Result.Seg, nil
	}
	return nil, fmt.Errorf("no paths found")
}
