// Package fswatch hotreloads VNet configs from a directory of `*.yaml`
// files into the operator's VNetPoolMap + AuthResolver.
package fswatch

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// Watcher monitors a directory for vnet config file changes and
// dynamically updates the in-memory VNetPoolMap and AuthResolver.
type Watcher struct {
	dir      string
	pools    *operator.VNetPoolMap
	resolver *auth.MapResolver
	watcher  *fsnotify.Watcher
	seed     uint32
	log      *log.Logger

	mu      sync.Mutex
	tracked map[string]common.VNI // filename -> VNI currently loaded
}

func NewWatcher(ctx context.Context, dir string, pools *operator.VNetPoolMap, resolver *auth.MapResolver, logger *log.Logger) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	seed, _ := rand.Int(rand.Reader, big.NewInt(1<<32))

	if logger == nil {
		logger = log.StandardLogger()
	}
	w := &Watcher{
		dir:      dir,
		pools:    pools,
		resolver: resolver,
		watcher:  fw,
		seed:     uint32(seed.Int64()),
		log:      logger,
		tracked:  make(map[string]common.VNI),
	}

	// Load all existing files on startup
	entries, err := os.ReadDir(dir)
	if err != nil {
		fw.Close()
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !isVNetFile(e.Name()) {
			continue
		}
		w.loadFile(filepath.Join(dir, e.Name()))
	}

	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, err
	}

	go w.loop(ctx)
	return w, nil
}

func (w *Watcher) Close() error { return w.watcher.Close() }

func (w *Watcher) loop(ctx context.Context) {
	defer w.watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			name := filepath.Base(event.Name)
			if !isVNetFile(name) {
				continue
			}

			switch {
			case event.Has(fsnotify.Create) || event.Has(fsnotify.Write):
				w.loadFile(event.Name)
			case event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename):
				w.removeFile(name)
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.log.Errorf("fswatch: %v", err)
		}
	}
}

func (w *Watcher) loadFile(path string) {
	cfg, err := common.LoadVNetConfig(path)
	if err != nil {
		w.log.Errorf("fswatch: %v", err)
		return
	}

	prefix, err := netip.ParsePrefix(cfg.CIDR)
	if err != nil {
		w.log.Errorf("fswatch: invalid cidr in %s: %v", path, err)
		return
	}

	vni := common.VNI(cfg.VNet)
	if !vni.Valid() {
		w.log.Errorf("fswatch: vni %d out of 24-bit range in %s", cfg.VNet, path)
		return
	}
	name := filepath.Base(path)

	w.mu.Lock()
	if oldVNI, ok := w.tracked[name]; ok && oldVNI != vni {
		w.pools.Remove(oldVNI)
		w.resolver.Remove(oldVNI)
		w.log.Infof("fswatch: removed old vni %s from %s", oldVNI, name)
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
			w.log.Errorf("fswatch: auth in %s: %v", path, err)
		} else {
			w.resolver.Set(vni, serverAuth)
		}
	} else {
		w.resolver.Remove(vni)
	}

	w.log.Infof("fswatch: loaded vni %s cidr=%s from %s", vni, prefix, name)
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
	w.log.Infof("fswatch: removed vni %s (file %s deleted)", vni, name)
}

func isVNetFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
