package k8s

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// Watcher is the k8s analog of fswatch.Watcher: an informer feeds Add /
// Update / Delete events for VNetConfig CRs, each translated into a
// (VNetPool, AuthResolver) entry on the supplied operator. Closing the
// Watcher tears the informer down; ctx is the shared lifetime.
type Watcher struct {
	pools    *operator.VNetPoolMap
	resolver *auth.MapResolver
	dyn      dynamic.Interface
	apiext   apiextcs.Interface
	ns       string
	seed     uint32
	log      *log.Logger

	mu      sync.Mutex
	tracked map[string]common.VNI // CR name → VNI currently loaded
	stop    chan struct{}
}

// Config is the wiring the caller hands to NewWatcher. The k8s REST
// client always uses in-cluster credentials (rest.InClusterConfig) — a
// gasoline-operator pod runs with a mounted ServiceAccount token; out-
// of-cluster modes go through the fswatch backend instead.
type Config struct {
	// Namespace scopes the informer. Required (VNetConfig is namespaced).
	Namespace string

	Pools    *operator.VNetPoolMap
	Resolver *auth.MapResolver
	Logger   *log.Logger
}

// NewWatcher builds REST clients, EnsureCRD's the VNetConfig schema,
// then starts a dynamic informer scoped to cfg.Namespace. The returned
// Watcher's lifetime is bound to ctx + Close.
func NewWatcher(ctx context.Context, cfg Config) (*Watcher, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s: in-cluster config: %w", err)
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("k8s: dynamic client: %w", err)
	}
	apiext, err := apiextcs.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("k8s: apiext client: %w", err)
	}
	if err := EnsureCRD(ctx, apiext); err != nil {
		return nil, err
	}

	seed, _ := rand.Int(rand.Reader, big.NewInt(1<<32))

	logger := cfg.Logger
	if logger == nil {
		logger = log.StandardLogger()
	}
	w := &Watcher{
		pools:    cfg.Pools,
		resolver: cfg.Resolver,
		dyn:      dyn,
		apiext:   apiext,
		ns:       cfg.Namespace,
		seed:     uint32(seed.Int64()),
		log:      logger,
		tracked:  make(map[string]common.VNI),
		stop:     make(chan struct{}),
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dyn, 30*time.Second, cfg.Namespace, nil)
	informer := factory.ForResource(GroupVersionResource).Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { w.onUpsert(o) },
		UpdateFunc: func(_, o any) { w.onUpsert(o) },
		DeleteFunc: func(o any) { w.onDelete(o) },
	}); err != nil {
		return nil, fmt.Errorf("k8s: add event handler: %w", err)
	}
	go func() {
		factory.Start(w.stop)
		factory.WaitForCacheSync(w.stop)
	}()
	go func() {
		<-ctx.Done()
		w.Close()
	}()
	return w, nil
}

// Close stops the informer factory. Idempotent.
func (w *Watcher) Close() error {
	defer func() { _ = recover() }() // close on already-closed
	close(w.stop)
	return nil
}

// onUpsert is the Add/Update branch: decode → translate → register.
func (w *Watcher) onUpsert(obj any) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		w.log.Errorf("k8s: unexpected event object type %T", obj)
		return
	}
	var cr VNetConfig
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &cr); err != nil {
		w.log.Errorf("k8s: decode %s: %v", u.GetName(), err)
		w.writeStatus(u, err)
		return
	}

	prefix, err := netip.ParsePrefix(cr.Spec.CIDR)
	if err != nil {
		w.log.Errorf("k8s: invalid cidr in %s: %v", cr.Name, err)
		w.writeStatus(u, err)
		return
	}
	vni := common.VNI(cr.Spec.VNet)
	if !vni.Valid() {
		err := fmt.Errorf("vni %d out of 24-bit range", cr.Spec.VNet)
		w.log.Errorf("k8s: %v in %s", err, cr.Name)
		w.writeStatus(u, err)
		return
	}

	w.mu.Lock()
	if oldVNI, ok := w.tracked[cr.Name]; ok && oldVNI != vni {
		w.pools.Remove(oldVNI)
		w.resolver.Remove(oldVNI)
		w.log.Infof("k8s: removed old vni %s from %s", oldVNI, cr.Name)
	}
	w.tracked[cr.Name] = vni
	w.mu.Unlock()

	pool := operator.NewVNetPool(vni, prefix, w.seed)
	w.pools.Add(vni, pool)

	if cr.Spec.Auth != "" {
		serverAuth, err := auth.ParseServerAuth(cr.Spec.Auth)
		if err != nil {
			w.log.Errorf("k8s: auth in %s: %v", cr.Name, err)
			w.writeStatus(u, err)
			return
		}
		w.resolver.Set(vni, serverAuth)
	} else {
		w.resolver.Remove(vni)
	}

	w.log.Infof("k8s: applied vni %s cidr=%s from %s", vni, prefix, cr.Name)
	w.writeStatus(u, nil)
}

// onDelete is the Delete branch: drop the matching VNI / auth entry.
func (w *Watcher) onDelete(obj any) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		// tombstone case
		if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			if uu, ok := t.Obj.(*unstructured.Unstructured); ok {
				u = uu
			}
		}
	}
	if u == nil {
		return
	}
	name := u.GetName()
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
	w.log.Infof("k8s: removed vni %s (CR %s deleted)", vni, name)
}

// writeStatus pushes LastApplied / LastError back to the CR's .status
// subresource. Best-effort: a status write failure is logged but doesn't
// roll back the in-memory pool change.
func (w *Watcher) writeStatus(u *unstructured.Unstructured, applyErr error) {
	status := map[string]any{
		"lastApplied":        metav1.Now().Format(time.RFC3339),
		"observedGeneration": u.GetGeneration(),
	}
	if applyErr != nil {
		status["lastError"] = applyErr.Error()
	} else {
		status["lastError"] = ""
	}
	patch := map[string]any{"status": status}
	merged := u.DeepCopy()
	_ = unstructured.SetNestedMap(merged.Object, status, "status")
	_, err := w.dyn.Resource(GroupVersionResource).Namespace(u.GetNamespace()).
		UpdateStatus(context.Background(), merged, metav1.UpdateOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		utilruntime.HandleError(fmt.Errorf("k8s: write status %s: %w", u.GetName(), err))
	}
	_ = patch
}

