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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultKeepAliveTimeout 		= 300 * time.Millisecond
	defaultKeepAliveInterval 		= 50 * time.Millisecond
	defaultKeepAliveTimeoutInterval	= 30 * time.Millisecond
	defaultMigrateGraceTimeout 		= 500 * time.Millisecond
)
var (
	defaultPathingConf = pathingConf{
		KeepAliveTimeout:         defaultKeepAliveTimeout,
		KeepAliveInterval:        defaultKeepAliveInterval,
		KeepAliveTimeoutInterval: defaultKeepAliveTimeoutInterval,
		MigrateGraceTimeout:      defaultMigrateGraceTimeout,
	}
)

type PathSorter interface {
	SortPaths([]snet.Path) []snet.Path
}
type leastHopsPathSorter struct {}
func (s leastHopsPathSorter) SortPaths(paths []snet.Path) []snet.Path {
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i].(sciond.Path), paths[j].(sciond.Path)
		return len(a.Interfaces()) < len(b.Interfaces())
	})
	return paths
}

type pathingConf struct {
	// KeepAliveInterval is the interval at which keep-alive messages are sent
	KeepAliveInterval time.Duration `yaml:"keepAliveInterval"`
	// KeepAliveTimeoutInterval is the interval between checking timeouts
	KeepAliveTimeoutInterval time.Duration `yaml:"keepAliveTimeoutInterval"`
	// KeepAliveTimeout is the timeout after which a path is to be considered inactive
	KeepAliveTimeout    time.Duration `yaml:"keepAliveTimeout"`
	// MigrateGraceTimeout is the first KeepAliveTimeout after a path migration
	MigrateGraceTimeout time.Duration `yaml:"migrateGraceTimeout"`
}

type pathMgr struct {
	conf             *pathingConf
	peer             *peer
	pathSorter       PathSorter
	pathsUpdateMutex sync.Mutex

	currPath	snet.Path
	paths       []snet.Path
	pathIdx     int
	hiddenPaths []snet.Path
	hiddenPathsIdx int

	// Probing
	isMigrating   int32
	lastMigration time.Time
	lastKeepAlive time.Time
}

func newPathMgr(conf *pathingConf, peer *peer) *pathMgr {
	pathMgr := &pathMgr{conf: conf, peer: peer, pathSorter: &leastHopsPathSorter{}}
	return pathMgr
}

// start is in charge of providing fresh paths to the peer
func (m *pathMgr) start() {
	m.resetTimeouts()
	if m.peer.remote.RendezvousAddr != nil {
		if err := m.sendHiddenPath(); err != nil {
			log.Error("Error sending paths to remote", "err", err)
		}
	}
	go m.keepAliveSender()
	go m.keepAliveChecker()
	go m.pathRefresher()
}

// pathRefresher periodically calls updatePathsToRemote
func (m *pathMgr) pathRefresher() {
	t := time.NewTicker(pathRefreshInterval)
	for {
		select {
		case <-t.C:
			_ = m.updatePathsToRemote()
		}
	}
}

// updatePathsToRemote retrieves new paths to remote and stores them
func (m *pathMgr) updatePathsToRemote() error {
	var (
		sdConn   = m.peer.gateway.sdConn
		localIA  = m.peer.remoteAddr().IA
		remoteIA = m.peer.gateway.localAddr().IA
	)
	paths, err := sdConn.Paths(context.Background(), localIA, remoteIA, sciond.PathReqFlags{Refresh: true})
	if err != nil { return err }

	// get unique paths by fingerprint
	pathsSet := make(map[snet.PathFingerprint]snet.Path)
	for _, path := range paths {
		f := path.Fingerprint()
		if _, ok := pathsSet[f]; ok {
			// Preferred first occurrences of same path
			continue
		}
		pathsSet[f] = path
	}
	var uniquePaths []snet.Path
	for _, path := range pathsSet {
		uniquePaths= append(uniquePaths, path)
	}

	uniquePaths = m.pathSorter.SortPaths(uniquePaths)
	log.Debug("Updated paths", "remote", remoteIA, "paths", uniquePaths)

	m.pathsUpdateMutex.Lock()
	defer m.pathsUpdateMutex.Unlock()
	m.paths = uniquePaths
	m.pathIdx = 0
	m.currPath = m.paths[m.pathIdx]
	return nil
}

func (m *pathMgr) nextPath(hidden bool) snet.Path {
	m.pathsUpdateMutex.Lock()
	defer m.pathsUpdateMutex.Unlock()
	if hidden && len(m.hiddenPaths) > 0 {
		if m.currPath == m.hiddenPaths[m.hiddenPathsIdx] && m.hiddenPathsIdx == len(m.hiddenPaths) - 1 {
			// We tried all hidden paths, switch to trying public paths
			m.hiddenPathsIdx = 0
			return m.paths[m.pathIdx]
		} else {
			m.hiddenPathsIdx = (m.hiddenPathsIdx + 1) % len(m.hiddenPaths)
			return m.hiddenPaths[m.hiddenPathsIdx]
		}
	} else {
		m.pathIdx = (m.pathIdx + 1) % len(m.paths)
		return m.paths[m.pathIdx]
	}
}

func (m *pathMgr) migrate() error {
	if !atomic.CompareAndSwapInt32(&m.isMigrating, 0, 1) {
		log.Debug("Another migrate operation is in progress")
		return nil
	}
	m.currPath = m.nextPath(*hiddenFailover)
	log.Info("Migrating connection", "path", ifacesToString(m.currPath.Interfaces()))

	err := m.peer.setupEgressConnections()
	if err != nil {
		m.isMigrating = 0
		return err
	}
	//go connFailHandler(client, client.DataConn.conn)
	//go connFailHandler(client, client.CtrlConn)
	go func() {
		// Wait KeepAliveTimeout before sending keepalive messages again to allow the other end to detect the failure
		time.Sleep(m.conf.KeepAliveTimeout)
		m.isMigrating = 0
		m.resetTimeouts()
	}()
	return nil
}

type RevocationHandler struct {}

// XXX: Not in use since revocation cannot be trusted to be reliable and to happen promptly
func (r *RevocationHandler) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	/*
	sRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(rawSRevInfo)
	if err != nil {
		log.Error("Revocation failed, unable to parse signed revocation info",
			"raw", rawSRevInfo, "err", err)
		return
	}
	revInfo, err := sRevInfo.RevInfo()
	if err != nil {
		log.Error("Error getting revocation info", "err", err)
	}
	log.Info("Received revocation", "info", revInfo)
	for _, client := range asClientMap {
		log.Info("Migrating client via revocation", "remote", client.Remote)
		go migrateClientPath(client, false)
	}
	*/
}

func (m *pathMgr) resetTimeouts() {
	// Give some time to set up things
	m.lastKeepAlive = time.Now().Add(m.conf.MigrateGraceTimeout)
}

func (m *pathMgr) keepAliveSender() {
	keepAliveMsg := &keepAliveMsg{}
	log.Debug("Sending keep alive messages ...")
	t := time.NewTicker(m.conf.KeepAliveInterval)
	for {
		select {
		case <-t.C:
			if m.isMigrating == 1 {
				log.Trace("Skipping keepAliveSender message during migration")
				continue
			}
			err := WriteMsg(keepAliveMsg, m.peer.egressCtrlEConn)
			switch err {
			case nil:
			case PeerIsMigratingError:
				log.Debug("Skipped keepAlive msg", "err", err)
			default:
				log.Error("Couldn't write keepAlive msg", "err", err)
			}
		}
	}
}

func (m *pathMgr) keepAliveChecker() {
	log.Debug("Checking keep alive messages ...")
	t := time.NewTicker(m.conf.KeepAliveTimeoutInterval)
	for {
		select {
		case <-t.C:
			if m.isMigrating == 1 {
				log.Trace("Skipping connProbing during migration")
				continue
			}
			if time.Now().Sub(m.lastKeepAlive) > m.conf.KeepAliveTimeout {
				log.Debug("Timeout expired, migrating to another path",
					"time", time.Now().Sub(m.lastKeepAlive),
					"remote", m.peer.remote.Address.IA)
				if err := m.migrate(); err != nil {
					log.Error("Migration failed", "err", err)
				}
			}
		}
	}
}

func (m *pathMgr) getCurrPath() snet.Path {
	return m.currPath
}

func (m *pathMgr) handleKeepAliveRequest(msg *keepAliveMsg) {
	log.Trace("New keepalive", "elapsed", time.Now().Sub(m.lastKeepAlive))
	m.lastKeepAlive = time.Now()
}

// TODO: Find a better way to get the overlay next hop
func (m *pathMgr) getOverlayNextHop() *net.UDPAddr {
	return m.paths[0].OverlayNextHop()
}

func (m *pathMgr) connFailHandler(conn *snet.Conn) {
	// XXX: Not relying on path revocation for fast fail-over, disabling for now
	return
	//b := make([]byte, common.MaxMTU)
	//for {
	//	_, _, err := conn.ReadFrom(b)
	//	if err != nil {
	//		log.Error("Unable to read ", "err", err)
	//		return
	//	}
	//}
}

