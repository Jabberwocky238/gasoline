package operator

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
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// Watcher monitors a directory for vnet config file changes and
// dynamically updates the in-memory VNetPoolMap and AuthResolver.
type Watcher struct {
	dir      string
	pools    *VNetPoolMap
	resolver *auth.MapResolver
	watcher  *fsnotify.Watcher
	seed     uint32
	log      *log.Logger

	mu      sync.Mutex
	tracked map[string][common.VNetIDLen]byte // filename -> vnetID currently loaded
}

func NewWatcher(ctx context.Context, dir string, pools *VNetPoolMap, resolver *auth.MapResolver, logger *log.Logger) (*Watcher, error) {
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
		tracked:  make(map[string][common.VNetIDLen]byte),
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

	vnetID := VNetIDFromUint64(cfg.VNet)
	name := filepath.Base(path)

	w.mu.Lock()
	if oldID, ok := w.tracked[name]; ok && oldID != vnetID {
		w.pools.Remove(oldID)
		w.resolver.Remove(oldID)
		w.log.Infof("fswatch: removed old vnet %x from %s", oldID, name)
	}
	w.tracked[name] = vnetID
	w.mu.Unlock()

	pool := NewVNetPool(vnetID, prefix, w.seed)
	w.pools.Add(vnetID, pool)

	authStr := ""
	if cfg.Auth != nil {
		authStr = cfg.Auth.String()
	}
	if authStr != "" {
		serverAuth, err := auth.ParseServerAuth(authStr)
		if err != nil {
			w.log.Errorf("fswatch: auth in %s: %v", path, err)
		} else {
			w.resolver.Set(vnetID, serverAuth)
		}
	} else {
		w.resolver.Remove(vnetID)
	}

	w.log.Infof("fswatch: loaded vnet %d (%x) cidr=%s from %s", cfg.VNet, vnetID, prefix, name)
}

func (w *Watcher) removeFile(name string) {
	w.mu.Lock()
	vnetID, ok := w.tracked[name]
	if ok {
		delete(w.tracked, name)
	}
	w.mu.Unlock()

	if !ok {
		return
	}

	w.pools.Remove(vnetID)
	w.resolver.Remove(vnetID)
	w.log.Infof("fswatch: removed vnet %x (file %s deleted)", vnetID, name)
}

func isVNetFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
