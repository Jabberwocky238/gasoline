// Package k8s is the Kubernetes-driven equivalent of the fswatch backend.
//
// Where fswatch monitors a directory of `vni-N.yaml` files and translates
// each into one (VNetPool, AuthResolver) entry, this package watches the
// VNetConfig CRD via an informer and does the same translation. The
// payload schema mirrors common.VnetConfig one-for-one (vnet / cidr /
// auth / anycast_ips), so a YAML on disk and a CR in the cluster are
// interchangeable.
//
// External deps (added by `go mod tidy` after first build):
//
//	k8s.io/apimachinery
//	k8s.io/client-go
//	k8s.io/apiextensions-apiserver
package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Group / version / resource constants for the VNetConfig CRD. Must
// match crd.go's CustomResourceDefinition object exactly.
const (
	GroupName = "gasoline.jabberwocky238.io"
	Version   = "v1alpha1"
	Kind      = "VNetConfig"
	Resource  = "vnetconfigs"
)

var (
	GroupVersion         = schema.GroupVersion{Group: GroupName, Version: Version}
	GroupVersionResource = GroupVersion.WithResource(Resource)
	GroupVersionKind     = GroupVersion.WithKind(Kind)
)

// VNetConfig is the typed CR. One CR == one VNet. Object name is
// conventionally "vni-<N>" so kubectl listings sort sensibly, but the
// spec.vnet field is the authoritative VNI.
type VNetConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VNetConfigSpec   `json:"spec,omitempty"`
	Status VNetConfigStatus `json:"status,omitempty"`
}

// VNetConfigSpec maps to common.VnetConfig: { vnet, cidr, auth }.
// Auth is the canonical "hmac:id:secret" string form. Empty Auth means
// "fall back to the operator's default". (anycast_ips is accepted by
// common.VnetConfig but not yet mirrored into the CRD schema.)
type VNetConfigSpec struct {
	VNet uint64 `json:"vnet"`
	CIDR string `json:"cidr"`
	Auth string `json:"auth,omitempty"`
}

// VNetConfigStatus is written back by the Watcher via the dynamic client
// so kubectl can show drift / errors.
type VNetConfigStatus struct {
	LastApplied        metav1.Time `json:"lastApplied,omitempty"`
	LastError          string      `json:"lastError,omitempty"`
	ObservedGeneration int64       `json:"observedGeneration,omitempty"`
}

type VNetConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VNetConfig `json:"items"`
}

// --------------- runtime.Object plumbing ---------------

func (in *VNetConfig) DeepCopyInto(out *VNetConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

func (in *VNetConfig) DeepCopy() *VNetConfig {
	if in == nil {
		return nil
	}
	out := new(VNetConfig)
	in.DeepCopyInto(out)
	return out
}

func (in *VNetConfig) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *VNetConfigStatus) DeepCopyInto(out *VNetConfigStatus) {
	*out = *in
	in.LastApplied.DeepCopyInto(&out.LastApplied)
}

func (in *VNetConfigList) DeepCopyInto(out *VNetConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]VNetConfig, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *VNetConfigList) DeepCopy() *VNetConfigList {
	if in == nil {
		return nil
	}
	out := new(VNetConfigList)
	in.DeepCopyInto(out)
	return out
}

func (in *VNetConfigList) DeepCopyObject() runtime.Object { return in.DeepCopy() }
