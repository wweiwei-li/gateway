// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package resource

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

// The loader must keep extension-managed resources unstructured. They are arbitrary
// custom kinds that are deliberately absent from the runtime scheme, so classifying
// them has to happen before the scheme conversion.
func TestLoadCustomExtensionKinds(t *testing.T) {
	eg := &egv1a1.EnvoyGateway{
		EnvoyGatewaySpec: egv1a1.EnvoyGatewaySpec{
			ExtensionManager: &egv1a1.ExtensionManager{
				PolicyResources: []egv1a1.GroupVersionKind{
					{Group: "example.extensions.io", Version: "v1alpha1", Kind: "ListenerContextExample"},
				},
				CertificateResources: []egv1a1.GroupVersionKind{
					{Group: "gateway.phoenix.aws", Version: "v1alpha1", Kind: "ACMCertificate"},
				},
			},
		},
	}

	in := []byte(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: example.extensions.io/v1alpha1
kind: ListenerContextExample
metadata:
  name: some-policy
  namespace: default
spec:
  username: user
---
apiVersion: gateway.phoenix.aws/v1alpha1
kind: ACMCertificate
metadata:
  name: app-cert
  namespace: default
spec:
  certificateArn: arn:aws:acm:us-east-1:123456789012:certificate/abc-123
status:
  conditions:
  - type: Ready
    status: "True"
    reason: Associated
`)

	got, err := LoadResourcesFromYAMLBytes(in, true, eg)
	require.NoError(t, err)

	require.Len(t, got.ExtensionServerPolicies, 1)
	require.Equal(t, "ListenerContextExample", got.ExtensionServerPolicies[0].GetKind())

	require.Len(t, got.ExtensionCertificates, 1)
	cert := got.ExtensionCertificates[0]
	require.Equal(t, "ACMCertificate", cert.GetKind())
	require.Equal(t, "gateway.phoenix.aws", cert.GroupVersionKind().Group)
	require.Equal(t, "app-cert", cert.GetName())
	require.Equal(t, "default", cert.GetNamespace())

	// The spec and status must survive intact -- the identifier comes from the spec and
	// admission gates on the Ready condition.
	arn, found, err := unstructured.NestedString(cert.Object, "spec", "certificateArn")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "arn:aws:acm:us-east-1:123456789012:certificate/abc-123", arn)

	conds, found, err := unstructured.NestedSlice(cert.Object, "status", "conditions")
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, conds, 1)
}
