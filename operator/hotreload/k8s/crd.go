package k8s

import (
	"context"
	"fmt"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EnsureCRD creates the VNetConfig CustomResourceDefinition in the cluster
// if it doesn't already exist. Idempotent: a NotFound check + Create; an
// existing CRD is left alone (no schema migration on bootup — that's a
// deliberate operator action, not a side-effect).
func EnsureCRD(ctx context.Context, cs apiextcs.Interface) error {
	crd := buildCRD()
	_, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crd.Name, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("k8s: get CRD %s: %w", crd.Name, err)
	}
	if _, err := cs.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("k8s: create CRD %s: %w", crd.Name, err)
	}
	return nil
}

// buildCRD constructs the CRD object matching the typed VNetConfig in
// types.go. Schema mirrors VNetConfigSpec / VNetConfigStatus exactly;
// adjust both files together.
func buildCRD() *apiextv1.CustomResourceDefinition {
	preserve := true
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: Resource + "." + GroupName,
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: GroupName,
			Scope: apiextv1.NamespaceScoped,
			Names: apiextv1.CustomResourceDefinitionNames{
				Plural:     Resource,
				Singular:   "vnetconfig",
				Kind:       Kind,
				ListKind:   Kind + "List",
				ShortNames: []string{"vnc"},
			},
			Versions: []apiextv1.CustomResourceDefinitionVersion{{
				Name:    Version,
				Served:  true,
				Storage: true,
				Subresources: &apiextv1.CustomResourceSubresources{
					Status: &apiextv1.CustomResourceSubresourceStatus{},
				},
				Schema: &apiextv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"spec": {
								Type:     "object",
								Required: []string{"vnet", "cidr"},
								Properties: map[string]apiextv1.JSONSchemaProps{
									"vnet": {Type: "integer", Minimum: float64Ptr(0), Maximum: float64Ptr(1<<24 - 1)},
									"cidr": {Type: "string"},
									"auth": {Type: "string"},
								},
							},
							"status": {
								Type:                   "object",
								XPreserveUnknownFields: &preserve,
							},
						},
					},
				},
				AdditionalPrinterColumns: []apiextv1.CustomResourceColumnDefinition{
					{Name: "VNI", Type: "integer", JSONPath: ".spec.vnet"},
					{Name: "CIDR", Type: "string", JSONPath: ".spec.cidr"},
					{Name: "Applied", Type: "date", JSONPath: ".status.lastApplied"},
				},
			}},
		},
	}
}

func float64Ptr(v float64) *float64 { return &v }
