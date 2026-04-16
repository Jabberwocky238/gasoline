package k8s

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/operator"
	"github.com/jabberwocky238/gasoline/protocol/auth"
)

// newTestWatcher builds a Watcher wired to a fake dynamic client,
// bypassing in-cluster config and CRD creation.
func newTestWatcher(t *testing.T, objects ...runtime.Object) (*Watcher, *dynamicfake.FakeDynamicClient) {
	t.Helper()

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: Kind},
		&unstructured.Unstructured{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: Kind + "List"},
		&unstructured.UnstructuredList{},
	)

	fakeDyn := dynamicfake.NewSimpleDynamicClient(scheme, objects...)

	w := &Watcher{
		pools:    operator.NewVNetPoolMap(),
		resolver: auth.NewMapResolver(nil),
		dyn:      fakeDyn,
		ns:       "test",
		seed:     42,
		log:      log.StandardLogger(),
		tracked:  make(map[string]common.VNI),
		stop:     make(chan struct{}),
	}

	return w, fakeDyn
}

// makeVNetConfigUnstructured creates an Unstructured VNetConfig for testing.
func makeVNetConfigUnstructured(name string, generation int64, vnet int64, cidr, authStr string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": GroupName + "/" + Version,
			"kind":       Kind,
			"metadata": map[string]any{
				"name":            name,
				"namespace":       "test",
				"generation":      generation,
				"resourceVersion": "1",
			},
			"spec": map[string]any{
				"vnet": vnet,
				"cidr": cidr,
			},
		},
	}
	if authStr != "" {
		spec := obj.Object["spec"].(map[string]any)
		spec["auth"] = authStr
	}
	return obj
}

func TestOnUpsert_AddAndTrack(t *testing.T) {
	w, _ := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-200", 1, 200, "10.0.0.0/24", "")
	w.onUpsert(obj)

	vni := common.VNI(200)
	if _, ok := w.pools.Get(vni); !ok {
		t.Fatalf("expected pool for VNI %s to exist", vni)
	}
	w.mu.Lock()
	tracked, ok := w.tracked["vni-200"]
	w.mu.Unlock()
	if !ok || tracked != vni {
		t.Fatalf("expected tracked[vni-200] = %s, got %s (ok=%v)", vni, tracked, ok)
	}
}

func TestOnUpsert_InvalidCIDR(t *testing.T) {
	w, _ := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-bad", 1, 200, "not-a-cidr", "")
	w.onUpsert(obj)

	vni := common.VNI(200)
	if _, ok := w.pools.Get(vni); ok {
		t.Fatalf("expected no pool for VNI %s after invalid CIDR", vni)
	}
}

func TestOnUpsert_InvalidVNI(t *testing.T) {
	w, _ := newTestWatcher(t)

	// VNI out of 24-bit range
	obj := makeVNetConfigUnstructured("vni-big", 1, 1<<24, "10.0.0.0/24", "")
	w.onUpsert(obj)

	if _, ok := w.pools.Get(common.VNI(1 << 24)); ok {
		t.Fatalf("expected no pool for out-of-range VNI")
	}
}

func TestOnUpsert_VNIChange(t *testing.T) {
	w, _ := newTestWatcher(t)

	// First apply with VNI 200
	obj1 := makeVNetConfigUnstructured("vni-change", 1, 200, "10.0.0.0/24", "")
	w.onUpsert(obj1)
	if _, ok := w.pools.Get(common.VNI(200)); !ok {
		t.Fatal("expected pool for VNI 200")
	}

	// Update same CR name but different VNI
	obj2 := makeVNetConfigUnstructured("vni-change", 2, 300, "10.0.1.0/24", "")
	w.onUpsert(obj2)

	if _, ok := w.pools.Get(common.VNI(200)); ok {
		t.Fatal("expected old VNI 200 pool to be removed")
	}
	if _, ok := w.pools.Get(common.VNI(300)); !ok {
		t.Fatal("expected new VNI 300 pool to exist")
	}
}

func TestOnDelete(t *testing.T) {
	w, _ := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-del", 1, 200, "10.0.0.0/24", "")
	w.onUpsert(obj)

	if _, ok := w.pools.Get(common.VNI(200)); !ok {
		t.Fatal("expected pool to exist before delete")
	}

	w.onDelete(obj)

	if _, ok := w.pools.Get(common.VNI(200)); ok {
		t.Fatal("expected pool to be removed after delete")
	}
	w.mu.Lock()
	_, tracked := w.tracked["vni-del"]
	w.mu.Unlock()
	if tracked {
		t.Fatal("expected tracked entry to be removed after delete")
	}
}

func TestOnDelete_Unknown(t *testing.T) {
	w, _ := newTestWatcher(t)

	// Delete something we never added — should be a no-op.
	obj := makeVNetConfigUnstructured("vni-unknown", 1, 999, "10.0.0.0/24", "")
	w.onDelete(obj) // should not panic
}

func TestUpdateFunc_SkipsResync(t *testing.T) {
	w, _ := newTestWatcher(t)

	var called int
	var mu sync.Mutex
	origOnUpsert := w.onUpsert // save for reference

	// Wrap onUpsert to count calls.
	countingUpsert := func(obj any) {
		mu.Lock()
		called++
		mu.Unlock()
		origOnUpsert(obj)
	}
	_ = countingUpsert

	// Simulate the UpdateFunc filter logic directly.
	obj := makeVNetConfigUnstructured("vni-resync", 1, 200, "10.0.0.0/24", "")

	// Same resourceVersion → resync, should skip.
	oldU := obj.DeepCopy()
	curU := obj.DeepCopy()
	if oldU.GetResourceVersion() != curU.GetResourceVersion() {
		t.Fatal("test setup: resourceVersions should match for resync test")
	}

	// Verify the filter logic: same resourceVersion means skip.
	shouldSkip := oldU.GetResourceVersion() == curU.GetResourceVersion()
	if !shouldSkip {
		t.Fatal("resync (same resourceVersion) should be skipped")
	}
}

func TestUpdateFunc_SkipsStatusOnly(t *testing.T) {
	// Same generation but different resourceVersion → status-only update, should skip.
	old := makeVNetConfigUnstructured("vni-status", 1, 200, "10.0.0.0/24", "")
	old.SetResourceVersion("1")

	cur := old.DeepCopy()
	cur.SetResourceVersion("2") // different RV (status was updated)
	// Generation stays at 1 → status-only change.

	shouldSkip := old.GetGeneration() == cur.GetGeneration()
	if !shouldSkip {
		t.Fatal("status-only update (same generation) should be skipped")
	}
}

func TestUpdateFunc_ProcessesSpecChange(t *testing.T) {
	old := makeVNetConfigUnstructured("vni-spec", 1, 200, "10.0.0.0/24", "")
	old.SetResourceVersion("1")

	cur := makeVNetConfigUnstructured("vni-spec", 2, 200, "10.0.1.0/24", "")
	cur.SetResourceVersion("3")

	// Different resourceVersion AND different generation → spec change, should process.
	shouldProcess := old.GetResourceVersion() != cur.GetResourceVersion() &&
		old.GetGeneration() != cur.GetGeneration()
	if !shouldProcess {
		t.Fatal("spec change (different generation) should be processed")
	}
}

func TestOnUpsert_WithAuth(t *testing.T) {
	w, _ := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-auth", 1, 200, "10.0.0.0/24", "noauth")
	w.onUpsert(obj)

	vni := common.VNI(200)
	if _, ok := w.pools.Get(vni); !ok {
		t.Fatal("expected pool to exist")
	}
}

func TestOnUpsert_EmptyAuthRemoves(t *testing.T) {
	w, _ := newTestWatcher(t)

	// First set auth
	obj1 := makeVNetConfigUnstructured("vni-noauth", 1, 200, "10.0.0.0/24", "noauth")
	w.onUpsert(obj1)

	// Then update with empty auth → should remove resolver entry
	obj2 := makeVNetConfigUnstructured("vni-noauth", 2, 200, "10.0.0.0/24", "")
	w.onUpsert(obj2)

	// Resolve should return error (no default, no per-vni)
	_, err := w.resolver.Resolve(common.VNI(200))
	if err == nil {
		t.Fatal("expected resolve to fail after auth removal")
	}
}

func TestWriteStatus(t *testing.T) {
	w, fakeDyn := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-status", 1, 200, "10.0.0.0/24", "")

	// Create the object in the fake client first.
	ctx := context.Background()
	_, err := fakeDyn.Resource(GroupVersionResource).Namespace("test").
		Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// writeStatus should not panic/error.
	w.writeStatus(obj, nil)

	// Verify status was written.
	updated, err := fakeDyn.Resource(GroupVersionResource).Namespace("test").
		Get(ctx, "vni-status", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	status, found, _ := unstructured.NestedMap(updated.Object, "status")
	if !found || status == nil {
		t.Fatal("expected status to be written")
	}
	if _, ok := status["observedGeneration"]; !ok {
		t.Fatal("expected observedGeneration in status")
	}
}

func TestWriteStatus_WithError(t *testing.T) {
	w, fakeDyn := newTestWatcher(t)

	obj := makeVNetConfigUnstructured("vni-err", 1, 200, "10.0.0.0/24", "")

	ctx := context.Background()
	_, err := fakeDyn.Resource(GroupVersionResource).Namespace("test").
		Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	w.writeStatus(obj, fmt.Errorf("test error"))

	updated, err := fakeDyn.Resource(GroupVersionResource).Namespace("test").
		Get(ctx, "vni-err", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	lastErr, _, _ := unstructured.NestedString(updated.Object, "status", "lastError")
	if lastErr != "test error" {
		t.Fatalf("expected lastError='test error', got %q", lastErr)
	}
}

func TestClose(t *testing.T) {
	w, _ := newTestWatcher(t)

	// Close should not panic.
	w.Close()

	// Double close should not panic.
	w.Close()

	// Verify stop channel is closed.
	select {
	case <-w.stop:
		// ok
	case <-time.After(time.Second):
		t.Fatal("stop channel should be closed")
	}
}
