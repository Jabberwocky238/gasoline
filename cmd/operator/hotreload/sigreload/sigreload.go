// Package sigreload hotreloads VNet configs by rescanning a directory on SIGHUP.
//
// It mirrors fswatch's effect but is driven by an explicit signal instead of
// inotify, which is useful when:
//   - the config dir lives on a filesystem that does not deliver fsnotify events
//     (overlayfs, some bind mounts, NFS)
//   - the operator is meant to reload atomically on `systemctl reload` rather than
//     on every partial file write.
package sigreload

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/cmd/operator"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/common/config"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// Watcher rescans `dir` on SIGHUP and syncs the VNetPoolMap + AuthResolver
// with the current on-disk set of *.yaml / *.yml files.
type Watcher struct {
	dir      string
	pools    *operator.VNetPoolMap
	resolver *auth.MapResolver
	seed     uint32
	log      *log.Logger

	sigs chan os.Signal
	done chan struct{}

	mu      sync.Mutex
	tracked map[string]common.VNI // filename -> VNI currently loaded
}

func NewWatcher(ctx context.Context, dir string, pools *operator.VNetPoolMap, resolver *auth.MapResolver, logger *log.Logger) (*Watcher, error) {
	if logger == nil {
		logger = log.StandardLogger()
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	seed, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	w := &Watcher{
		dir:      dir,
		pools:    pools,
		resolver: resolver,
		seed:     uint32(seed.Int64()),
		log:      logger,
		sigs:     make(chan os.Signal, 1),
		done:     make(chan struct{}),
		tracked:  make(map[string]common.VNI),
	}

	w.rescan()

	signal.Notify(w.sigs, syscall.SIGHUP)
	go w.loop(ctx)
	return w, nil
}

func (w *Watcher) Close() error {
	signal.Stop(w.sigs)
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	return nil
}

func (w *Watcher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case sig := <-w.sigs:
			w.log.Infof("sigreload: received %s, rescanning %s", sig, w.dir)
			w.rescan()
		}
	}
}

// rescan synchronises the in-memory state with the directory contents:
// every vnet file still present is (re)loaded; every tracked file now absent is removed.
func (w *Watcher) rescan() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.log.Errorf("sigreload: read %s: %v", w.dir, err)
		return
	}

	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isVNetFile(name) {
			continue
		}
		present[name] = struct{}{}
		w.loadFile(filepath.Join(w.dir, name))
	}

	w.mu.Lock()
	var stale []string
	for name := range w.tracked {
		if _, ok := present[name]; !ok {
			stale = append(stale, name)
		}
	}
	w.mu.Unlock()
	for _, name := range stale {
		w.removeFile(name)
	}
}

func (w *Watcher) loadFile(path string) {
	cfg, err := config.LoadVNetConfig(path)
	if err != nil {
		w.log.Errorf("sigreload: %v", err)
		return
	}

	prefix, err := netip.ParsePrefix(cfg.CIDR)
	if err != nil {
		w.log.Errorf("sigreload: invalid cidr in %s: %v", path, err)
		return
	}

	vni := common.VNI(cfg.VNet)
	if !vni.Valid() {
		w.log.Errorf("sigreload: vni %d out of 24-bit range in %s", cfg.VNet, path)
		return
	}
	name := filepath.Base(path)

	w.mu.Lock()
	if oldVNI, ok := w.tracked[name]; ok && oldVNI != vni {
		w.pools.Remove(oldVNI)
		w.resolver.Remove(oldVNI)
		w.log.Infof("sigreload: removed old vni %s from %s", oldVNI, name)
	}
	w.tracked[name] = vni
	w.mu.Unlock()

	pool := operator.NewVNetPool(vni, prefix, w.seed)
	w.pools.Add(vni, pool)

	authStr := ""
	if cfg.Auth != nil {
		authStr = cfg.Auth.String()
	}
	if authStr != "" {
		serverAuth, err := auth.ParseServerAuth(authStr)
		if err != nil {
			w.log.Errorf("sigreload: auth in %s: %v", path, err)
		} else {
			w.resolver.Set(vni, serverAuth)
		}
	} else {
		w.resolver.Remove(vni)
	}

	w.log.Infof("sigreload: loaded vni %s cidr=%s from %s", vni, prefix, name)
}

func (w *Watcher) removeFile(name string) {
	w.mu.Lock()
	vni, ok := w.tracked[name]
	if ok {
		delete(w.tracked, name)
	}
	w.mu.Unlock()
	if !ok {
		return
	}
	w.pools.Remove(vni)
	w.resolver.Remove(vni)
	w.log.Infof("sigreload: removed vni %s (file %s gone)", vni, name)
}

func isVNetFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
