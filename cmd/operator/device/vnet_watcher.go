package operator

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/jabberwocky238/gasoline/protocol"
)

// vnetWatcher loads vnet YAML files from --root and keeps Raft in sync with
// them (PRD §4.4). The files are only triggers: on start it scans the dir and
// upserts each; then fsnotify drives incremental reloads. Raft holds the
// authoritative state (version-greatest wins), so this only ever proposes
// upserts — it never reads another operator's files.
type vnetWatcher struct {
	op   *Operator
	dir  string
	fsw  *fsnotify.Watcher
	stop chan struct{}
}

// startVNetWatcher scans dir once, upserts what it finds, then watches for
// changes. Requires an attached consensus node (vnets are Raft state). Returns
// nil (no watcher) when dir is empty or no node is attached.
func (o *Operator) startVNetWatcher(dir string) (*vnetWatcher, error) {
	if dir == "" || o.state.node == nil {
		return nil, nil
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fsw.Add(dir); err != nil {
		_ = fsw.Close()
		return nil, err
	}
	w := &vnetWatcher{op: o, dir: dir, fsw: fsw, stop: make(chan struct{})}
	// The initial scan runs in the reconcile loop, not here: at Start() the Raft
	// cluster may not have a leader yet, so a synchronous upsert would fail and
	// never retry (the file won't change to re-trigger fsnotify). The reconcile
	// loop re-scans until every file's version is reflected in the FSM.
	go w.loop()
	return w, nil
}

func (w *vnetWatcher) close() {
	if w == nil {
		return
	}
	close(w.stop)
	_ = w.fsw.Close()
}

// scanAll loads every vnet file in the dir and upserts it.
func (w *vnetWatcher) scanAll() {
	files, err := LoadVNetDir(w.dir)
	if err != nil {
		w.op.lctx.Log().Warnf("vnet root scan %q: %v", w.dir, err)
		return
	}
	for _, vf := range files {
		w.upsert(vf)
	}
}

// loop consumes fsnotify events. A create/write reloads that one file; a
// remove/rename is logged (removing a vnet from Raft on file deletion needs an
// explicit delete command — see the note below).
func (w *vnetWatcher) loop() {
	// Debounce: editors emit several writes per save; coalesce a burst into one
	// reload per file.
	pending := make(map[string]time.Time)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	// Reconcile: periodically re-scan and upsert anything whose file version is
	// ahead of the FSM. This drives the INITIAL load (deferred from Start until
	// a leader exists) and heals transient leader loss — an upsert that failed
	// with "not the leader" is retried on the next tick. Fast at first, then
	// backs off to a slow heartbeat once everything is synced.
	w.scanAll()
	reconcile := time.NewTicker(1 * time.Second)
	defer reconcile.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-reconcile.C:
			w.scanAll()
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if !isYAML(ev.Name) {
				continue
			}
			switch {
			case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
				pending[ev.Name] = time.Now()
			case ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0:
				// A file vanished. We don't know its VNI without the content, so
				// deletion-by-file is a follow-up (needs a filename->VNI index or
				// a VNetDelete command). Log for now (PRD §4.4 delete path).
				w.op.lctx.Log().Infof("vnet file removed %q (delete not yet propagated)", ev.Name)
				delete(pending, ev.Name)
			}
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.op.lctx.Log().Warnf("vnet watch error: %v", err)
		case <-tick.C:
			now := time.Now()
			for path, t := range pending {
				if now.Sub(t) < 200*time.Millisecond {
					continue
				}
				delete(pending, path)
				w.reloadOne(path)
			}
		}
	}
}

func (w *vnetWatcher) reloadOne(path string) {
	vf, err := LoadVNetFile(path)
	if err != nil {
		w.op.lctx.Log().Warnf("vnet reload %q: %v", path, err)
		return
	}
	w.upsert(vf)
}

// upsert proposes the file to Raft iff its version is newer than what the FSM
// holds. The FSM re-checks the version at apply time (the authoritative gate);
// this pre-check just avoids a needless proposal when nothing changed.
func (w *vnetWatcher) upsert(vf *VNetFile) {
	vni := protocol.VNI_Ty(vf.VNI)
	if cur, ok := w.op.state.node.VNetVersion(vni); ok && vf.Version <= cur {
		return // FSM already has this version or newer
	}
	up, err := vf.ToUpsert()
	if err != nil {
		w.op.lctx.Log().Warnf("vnet %d: build upsert: %v", vf.VNI, err)
		return
	}
	if err := w.op.state.node.UpsertVNet(up, 5*time.Second); err != nil {
		w.op.lctx.Log().Warnf("vnet %d: upsert v%d: %v", vf.VNI, vf.Version, err)
		return
	}
	w.op.lctx.Log().Infof("vnet %d: upserted from %s (v%d)", vf.VNI, w.dir, vf.Version)
	w.op.ensureVNIRegistered(vni)
}

func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

// ensureVNIRegistered makes sure the operator has a local vniEntry for vni so
// clients can be admitted on it. The authoritative vnet definition lives in the
// FSM; this only creates the local runtime container if absent.
func (o *Operator) ensureVNIRegistered(vni protocol.VNI_Ty) {
	if _, ok := o.state.vni(vni); ok {
		return
	}
	// Authorization is enforced against the FSM key table at handshake time, so
	// the local authorizedKeys set may be empty here.
	o.state.registerVNI(vni, nil)
}
