// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/envoyproxy/gateway/internal/ir"
)

func extensionRefCert(name string) ir.TLSCertificate {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetName("app-cert")
	obj.SetNamespace("default")
	return ir.TLSCertificate{Name: name, ExtensionRef: &ir.UnstructuredRef{Object: obj}}
}

// The point of the whole design: when a data plane resolves a certificate name itself, the
// filter chain must carry the name alone. Every other branch in buildXdsDownstreamTLSSocket
// populates SdsConfig, so a nil returned by the extension has to survive untouched.
func TestExtensionCertificateNilSdsConfigIsPreserved(t *testing.T) {
	const certIdentifier = "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"

	tlsConfig := &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}}
	resolutions := map[string]*tlsv3.SdsSecretConfig{
		// No SdsConfig: the data plane resolves the name internally.
		"ext-cert": {Name: certIdentifier},
	}

	tSocket, err := buildXdsDownstreamTLSSocket(tlsConfig, resolutions)
	require.NoError(t, err)
	require.NotNil(t, tSocket)

	tlsCtx := &tlsv3.DownstreamTlsContext{}
	require.NoError(t, tSocket.GetTypedConfig().UnmarshalTo(tlsCtx))

	configs := tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	require.Len(t, configs, 1)
	require.Equal(t, certIdentifier, configs[0].GetName())
	require.Nil(t, configs[0].GetSdsConfig(), "a nil SdsConfig must not be defaulted to a config source")
}

// An extension-resolved certificate never yields an Envoy Gateway served secret, so no key
// material enters the xDS stream for it.
func TestExtensionCertificateEmitsNoSecret(t *testing.T) {
	cert := extensionRefCert("ext-cert")
	require.Nil(t, buildXdsTLSCertSecret(&cert))
}

// A certificate the extension did not resolve is omitted rather than emitted as a reference
// to a secret that is never sent, so the listener fails closed.
func TestUnresolvedExtensionCertificateIsOmitted(t *testing.T) {
	tlsConfig := &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}}

	for name, resolutions := range map[string]map[string]*tlsv3.SdsSecretConfig{
		"no resolutions at all": nil,
		"a nil entry":           {"ext-cert": nil},
		"a different cert":      {"other": {Name: "unrelated"}},
	} {
		t.Run(name, func(t *testing.T) {
			tSocket, err := buildXdsDownstreamTLSSocket(tlsConfig, resolutions)
			require.NoError(t, err)

			tlsCtx := &tlsv3.DownstreamTlsContext{}
			require.NoError(t, tSocket.GetTypedConfig().UnmarshalTo(tlsCtx))
			require.Empty(t, tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs())
		})
	}
}

// Mixed TLS on one listener: a Secret-backed certificate and an extension-resolved one must
// coexist, the first served by Envoy Gateway over ADS and the second by name alone.
func TestMixedSecretAndExtensionCertificates(t *testing.T) {
	tlsConfig := &ir.TLSConfig{Certificates: []ir.TLSCertificate{
		{Name: "default/tls-secret", Certificate: []byte("cert"), PrivateKey: []byte("key")},
		extensionRefCert("ext-cert"),
	}}
	resolutions := map[string]*tlsv3.SdsSecretConfig{
		"ext-cert": {Name: "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"},
	}

	tSocket, err := buildXdsDownstreamTLSSocket(tlsConfig, resolutions)
	require.NoError(t, err)

	tlsCtx := &tlsv3.DownstreamTlsContext{}
	require.NoError(t, tSocket.GetTypedConfig().UnmarshalTo(tlsCtx))

	configs := tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	require.Len(t, configs, 2)

	require.Equal(t, "default/tls-secret", configs[0].GetName())
	require.NotNil(t, configs[0].GetSdsConfig(), "an Envoy Gateway served secret still uses ADS")

	require.Equal(t, "arn:aws:acm:us-east-1:123456789012:certificate/abc-123", configs[1].GetName())
	require.Nil(t, configs[1].GetSdsConfig())
}

func TestSplitIRListenerName(t *testing.T) {
	tests := []struct {
		in                              string
		wantNS, wantGateway, wantLisner string
	}{
		{"default/my-gateway/https", "default", "my-gateway", "https"},
		{"default/my-gateway", "default", "my-gateway", ""},
		{"https", "", "", "https"},
	}

	for _, tc := range tests {
		ns, gw, l := splitIRListenerName(tc.in)
		require.Equal(t, tc.wantNS, ns, tc.in)
		require.Equal(t, tc.wantGateway, gw, tc.in)
		require.Equal(t, tc.wantLisner, l, tc.in)
	}
}
