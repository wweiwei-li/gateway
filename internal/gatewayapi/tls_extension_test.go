// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

const (
	testCertGroup = "gateway.phoenix.aws"
	testCertKind  = "ACMCertificate"
	testCertARN   = "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"
)

func extensionCertificate(namespace, name string, ready *bool, reason string) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": testCertGroup + "/v1alpha1",
		"kind":       testCertKind,
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"certificateArn": testCertARN,
		},
	}

	if ready != nil {
		condStatus := string(metav1.ConditionFalse)
		if *ready {
			condStatus = string(metav1.ConditionTrue)
		}
		obj["status"] = map[string]interface{}{
			"conditions": []interface{}{
				map[string]interface{}{
					"type":    "Ready",
					"status":  condStatus,
					"reason":  reason,
					"message": "from the provider",
				},
			},
		}
	}

	return unstructured.Unstructured{Object: obj}
}

// listenerWithExtensionCertRef builds a single HTTPS listener whose only certificate ref
// points at an extension-registered kind.
func listenerWithExtensionCertRef(t *testing.T, namespace string) *ListenerContext {
	t.Helper()

	group := gwapiv1.Group(testCertGroup)
	kind := gwapiv1.Kind(testCertKind)
	gw := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: namespace},
		Spec: gwapiv1.GatewaySpec{
			Listeners: []gwapiv1.Listener{{
				Name:     "https",
				Protocol: gwapiv1.HTTPSProtocolType,
				Port:     443,
				TLS: &gwapiv1.ListenerTLSConfig{
					Mode: ptr.To(gwapiv1.TLSModeTerminate),
					CertificateRefs: []gwapiv1.SecretObjectReference{{
						Group: &group,
						Kind:  &kind,
						Name:  "app-cert",
					}},
				},
			}},
		},
	}

	gwCtx := &GatewayContext{Gateway: gw}
	gwCtx.ResetListeners()
	require.Len(t, gwCtx.listeners, 1)
	return gwCtx.listeners[0]
}

// A certificate ref to a registered extension kind is admitted only when the provider
// reports Ready=True, and the resolved certificate carries no key material.
func TestExtensionCertificateRefAdmission(t *testing.T) {
	translator := &Translator{
		ExtensionCertificateGroupKinds: []schema.GroupKind{
			{Group: testCertGroup, Kind: testCertKind},
		},
	}

	tests := []struct {
		name       string
		cert       *unstructured.Unstructured
		wantOK     bool
		wantReason gwapiv1.ListenerConditionReason
	}{
		{
			name:   "ready certificate is admitted",
			cert:   ptr.To(extensionCertificate("default", "app-cert", ptr.To(true), "Associated")),
			wantOK: true,
		},
		{
			name:       "not ready certificate is refused with the provider's reason",
			cert:       ptr.To(extensionCertificate("default", "app-cert", ptr.To(false), "AssociationInProgress")),
			wantOK:     false,
			wantReason: gwapiv1.ListenerReasonPending,
		},
		{
			name:       "certificate with no Ready condition is refused",
			cert:       ptr.To(extensionCertificate("default", "app-cert", nil, "")),
			wantOK:     false,
			wantReason: gwapiv1.ListenerReasonPending,
		},
		{
			name:       "absent certificate is an invalid ref",
			cert:       nil,
			wantOK:     false,
			wantReason: gwapiv1.ListenerReasonInvalidCertificateRef,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &resource.Resources{}
			if tc.cert != nil {
				res.ExtensionCertificates = []unstructured.Unstructured{*tc.cert}
			}

			listener := listenerWithExtensionCertRef(t, "default")
			secrets, extCerts, _, ok := translator.validateTerminateModeAndGetTLSSecrets(listener, res)

			require.Equal(t, tc.wantOK, ok)
			require.Empty(t, secrets, "an extension certificate must not appear as a Secret")

			if !tc.wantOK {
				require.Empty(t, extCerts)
				var reasons []string
				for _, c := range listener.GetConditions() {
					reasons = append(reasons, c.Reason)
				}
				require.Contains(t, reasons, string(tc.wantReason))
				return
			}

			require.Len(t, extCerts, 1)
			listener.SetTLSExtensionCertificates(extCerts)

			// The IR must carry a reference, never key material.
			irTLS := irTLSConfigs(&listener.tls)
			require.NotNil(t, irTLS)
			require.Len(t, irTLS.Certificates, 1)
			cert := irTLS.Certificates[0]
			require.NotNil(t, cert.ExtensionRef)
			require.Nil(t, cert.SDS)
			require.Empty(t, cert.Certificate)
			require.Empty(t, cert.PrivateKey)
			require.NoError(t, cert.Validate())

			arn, found, err := unstructured.NestedString(cert.ExtensionRef.Object.Object, "spec", "certificateArn")
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, testCertARN, arn)
		})
	}
}

// A ref to an unregistered group and kind must still be rejected, so the relaxed gate does
// not become a hole for arbitrary kinds.
func TestUnregisteredCertificateKindStillRejected(t *testing.T) {
	translator := &Translator{}

	listener := listenerWithExtensionCertRef(t, "default")
	res := &resource.Resources{
		ExtensionCertificates: []unstructured.Unstructured{
			extensionCertificate("default", "app-cert", ptr.To(true), "Associated"),
		},
	}

	_, extCerts, _, ok := translator.validateTerminateModeAndGetTLSSecrets(listener, res)
	require.False(t, ok)
	require.Empty(t, extCerts)
}

// consumerEntry builds one status.consumers entry: a reference naming the consuming Gateway and
// that consumer's own conditions.
func consumerEntry(kind, namespace, name string, ready *bool, reason string) map[string]interface{} {
	return consumerEntryInGroup(gwapiv1.GroupName, kind, namespace, name, ready, reason)
}

// consumerEntryInGroup is consumerEntry with the reference group spelled out, for the cases where
// the group is what decides whether the entry matches.
func consumerEntryInGroup(group, kind, namespace, name string, ready *bool, reason string) map[string]interface{} {
	entry := map[string]interface{}{
		"consumerRef": map[string]interface{}{
			"group":     group,
			"kind":      kind,
			"namespace": namespace,
			"name":      name,
		},
	}
	if ready != nil {
		condStatus := string(metav1.ConditionFalse)
		if *ready {
			condStatus = string(metav1.ConditionTrue)
		}
		entry["conditions"] = []interface{}{
			map[string]interface{}{
				"type":   "Ready",
				"status": condStatus,
				"reason": reason,
			},
		}
	}
	return entry
}

// withExtraFields adds provider-specific fields to a consumers entry, standing in for whatever a
// real provider records alongside the parts Envoy Gateway reads.
func withExtraFields(entry, extra map[string]interface{}) map[string]interface{} {
	for k, v := range extra {
		entry[k] = v
	}
	return entry
}

// certificateWithConsumers builds a certificate reporting readiness per consumer rather than once
// overall.
func certificateWithConsumers(namespace, name string, consumers ...map[string]interface{}) unstructured.Unstructured {
	entries := make([]interface{}, 0, len(consumers))
	for _, c := range consumers {
		entries = append(entries, c)
	}
	obj := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": testCertGroup + "/v1alpha1",
		"kind":       testCertKind,
		"metadata": map[string]interface{}{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]interface{}{
			"certificateARN": testCertARN,
		},
		"status": map[string]interface{}{
			"consumers": entries,
		},
	}}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: testCertGroup, Version: "v1alpha1", Kind: testCertKind})
	return obj
}

// A certificate may report readiness once for itself or once per consuming Gateway. The
// per-consumer shape exists because the same certificate can be usable by one Gateway and not yet
// by another -- a provider whose certificates reach each proxy separately cannot describe both with
// a single condition.
//
// The single-condition shape stays the default: a provider that does not populate status.consumers
// must keep working exactly as before, which is what makes the per-consumer shape additive.
func TestExtensionCertificateReadyPerConsumer(t *testing.T) {
	const (
		gwNamespace = "team-a"
		gwName      = "web-gateway"
	)

	tests := []struct {
		name       string
		obj        unstructured.Unstructured
		wantReady  bool
		wantReason string
	}{
		{
			// No status.consumers at all, so the top-level condition is authoritative.
			name:      "falls back to the single condition when ready",
			obj:       extensionCertificate("default", "app-cert", ptr.To(true), "Associated"),
			wantReady: true,
		},
		{
			name:       "falls back to the single condition when not ready",
			obj:        extensionCertificate("default", "app-cert", ptr.To(false), "AssociationInProgress"),
			wantReady:  false,
			wantReason: "AssociationInProgress",
		},
		{
			name:       "falls back to the single condition when absent",
			obj:        extensionCertificate("default", "app-cert", nil, ""),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			name: "this Gateway's entry reports ready",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry(resource.KindGateway, gwNamespace, gwName, ptr.To(true), "Associated")),
			wantReady: true,
		},
		{
			// The provider's own reason travels, so the listener explains the delay in the
			// provider's terms rather than a generic one.
			name: "this Gateway's entry reports not ready and its reason is forwarded",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry(resource.KindGateway, gwNamespace, gwName, ptr.To(false), "AssociationInProgress")),
			wantReady:  false,
			wantReason: "AssociationInProgress",
		},
		{
			// The case the shape exists for: one certificate, two Gateways, different answers.
			name: "two consumers resolve independently",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry(resource.KindGateway, gwNamespace, gwName, ptr.To(true), "Associated"),
				consumerEntry(resource.KindGateway, "team-b", "api-gateway", ptr.To(false), "AssociationInProgress")),
			wantReady: true,
		},
		{
			// status.consumers is present but says nothing about this Gateway. The provider has
			// made no statement, so admitting would be a guess.
			name: "no entry for this Gateway is not ready",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry(resource.KindGateway, "team-b", "api-gateway", ptr.To(true), "Associated")),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			name:       "an empty consumers list is not ready",
			obj:        certificateWithConsumers("default", "app-cert"),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			// A matching reference carrying no conditions is a statement that says nothing.
			name: "a matching entry with no conditions is not ready",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry(resource.KindGateway, gwNamespace, gwName, nil, "")),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			// Names can collide across kinds, so a non-Gateway reference must not match.
			name: "an entry for another kind with the same name does not match",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntry("ListenerSet", gwNamespace, gwName, ptr.To(true), "Associated")),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			// "Gateway" is not a unique kind, so the group has to be matched too. Otherwise an
			// entry describing an unrelated object of the same namespace, name and kind would
			// satisfy the gate and the listener would be programmed on someone else's readiness.
			name: "an entry for a Gateway in another group does not match",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntryInGroup("bedrock-agentcore.aws", resource.KindGateway,
					gwNamespace, gwName, ptr.To(true), "Associated")),
			wantReady:  false,
			wantReason: string(gwapiv1.ListenerReasonPending),
		},
		{
			// Both group and kind default to the Gateway API Gateway, so a provider may leave
			// them out.
			name: "an entry omitting group and kind matches",
			obj: certificateWithConsumers("default", "app-cert",
				consumerEntryInGroup("", "", gwNamespace, gwName, ptr.To(true), "Associated")),
			wantReady: true,
		},
		{
			// A provider records its own detail on the entry -- which proxy served it, which
			// controller wrote it. Envoy Gateway reads the reference and the conditions and must
			// ignore the rest rather than failing to match.
			name: "provider-specific fields on the entry are ignored",
			obj: certificateWithConsumers("default", "app-cert",
				withExtraFields(
					consumerEntry(resource.KindGateway, gwNamespace, gwName, ptr.To(true), "Associated"),
					map[string]interface{}{
						"proxyARN":       "arn:example:proxy/P1",
						"controllerName": "example.io/certificate-provider",
					})),
			wantReady: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ready, reason, _ := extensionCertificateReady(&tc.obj, gwNamespace, gwName)
			require.Equal(t, tc.wantReady, ready)
			if tc.wantReason != "" {
				require.Equal(t, tc.wantReason, reason)
			}
		})
	}
}
