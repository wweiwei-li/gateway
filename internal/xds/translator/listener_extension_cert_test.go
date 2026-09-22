// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"os"
	"testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/xds/types"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	quicv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"
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
		// A ListenerSet listener is named gwNs/gwName/lsNs/lsName/listenerName. The Gateway
		// is what identifies the consumer to an extension, so it must survive the extra pair;
		// falling through to the default case would hand the hook an empty Gateway and a
		// resolver answering per Gateway would refuse every ListenerSet listener.
		{"team-a/web-gateway/team-a/extra-listeners/https", "team-a", "web-gateway", "https"},
	}

	for _, tc := range tests {
		ns, gw, l := splitIRListenerName(tc.in)
		require.Equal(t, tc.wantNS, ns, tc.in)
		require.Equal(t, tc.wantGateway, gw, tc.in)
		require.Equal(t, tc.wantLisner, l, tc.in)
	}
}

// A listener whose every certificate went unresolved must not be emitted.
//
// This is the case the earlier tests left open: TestUnresolvedExtensionCertificateIsOmitted
// asserts the certificate is dropped from the filter chain, which is right when another
// certificate remains. When it was the only one, the filter chain would carry an empty
// tls_certificate_sds_secret_configs and Envoy rejects the update, leaving the proxy on its last
// known good config -- so nothing looks wrong until it restarts with no last known good to fall
// back to. Verified against a real proxy: "Error adding/updating listener(s)
// default/cert-test/https: Unknown static secret: <arn>", followed by a NACK.
func TestHasNoServableCertificate(t *testing.T) {
	resolved := map[string]*tlsv3.SdsSecretConfig{"ext-cert": {Name: "identifier"}}

	tests := []struct {
		name        string
		tlsConfig   *ir.TLSConfig
		resolutions map[string]*tlsv3.SdsSecretConfig
		want        bool
	}{
		{
			name:      "nil config is not our concern",
			tlsConfig: nil,
			want:      false,
		},
		{
			name:      "no certificates at all is not our concern",
			tlsConfig: &ir.TLSConfig{},
			want:      false,
		},
		{
			name:        "sole extension certificate resolved",
			tlsConfig:   &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}},
			resolutions: resolved,
			want:        false,
		},
		{
			name:        "sole extension certificate unresolved",
			tlsConfig:   &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}},
			resolutions: nil,
			want:        true,
		},
		{
			name:        "sole extension certificate resolved to a nil entry",
			tlsConfig:   &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}},
			resolutions: map[string]*tlsv3.SdsSecretConfig{"ext-cert": nil},
			want:        true,
		},
		{
			name:        "sole extension certificate resolved to an empty name",
			tlsConfig:   &ir.TLSConfig{Certificates: []ir.TLSCertificate{extensionRefCert("ext-cert")}},
			resolutions: map[string]*tlsv3.SdsSecretConfig{"ext-cert": {Name: ""}},
			want:        true,
		},
		{
			name: "one of two extension certificates resolved -- serve the narrower set",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				extensionRefCert("ext-cert"),
				extensionRefCert("other"),
			}},
			resolutions: resolved,
			want:        false,
		},
		{
			name: "a Secret alongside an unresolved extension certificate is still servable",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				{Name: "secret-cert", Certificate: []byte("cert"), PrivateKey: []byte("key")},
				extensionRefCert("ext-cert"),
			}},
			resolutions: nil,
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, hasNoServableCertificate(tc.tlsConfig, tc.resolutions))
		})
	}
}

// A listener left with no filter chains is dropped rather than sent empty.
func TestPruneEmptyTLSListeners(t *testing.T) {
	empty := &listenerv3.Listener{Name: "no-chains"}
	withChain := &listenerv3.Listener{
		Name:         "has-a-chain",
		FilterChains: []*listenerv3.FilterChain{{Name: "fc"}},
	}
	withDefault := &listenerv3.Listener{
		Name:               "has-a-default-chain",
		DefaultFilterChain: &listenerv3.FilterChain{Name: "default"},
	}

	// A UDP listener has no filter chains at all -- it dispatches through listener filters --
	// so it must survive a pass that prunes chain-less listeners.
	udp := &listenerv3.Listener{
		Name:            "udp-route",
		ListenerFilters: []*listenerv3.ListenerFilter{{Name: "envoy.filters.udp_listener.udp_proxy"}},
	}

	tCtx := &types.ResourceVersionTable{
		XdsResources: types.XdsResources{
			resourcev3.ListenerType: []cachetypes.Resource{empty, withChain, withDefault, udp},
		},
	}

	pruneEmptyTLSListeners(tCtx, logging.DefaultLogger(os.Stderr, egv1a1.LogLevelError))

	var names []string
	for _, r := range tCtx.XdsResources[resourcev3.ListenerType] {
		names = append(names, r.(*listenerv3.Listener).GetName())
	}
	require.Equal(t, []string{"has-a-chain", "has-a-default-chain", "udp-route"}, names,
		"only the listener with nothing to serve should be dropped")
}

// A secret name is emitted at most once per filter chain.
//
// Two distinct extension-backed resources can resolve to one identifier, because the identifier
// belongs to the provider rather than to the resource: two resources naming the same underlying
// certificate is legitimate configuration that Envoy Gateway has no way to detect. Envoy caps how
// many certificates a TLS context may carry and tells them apart by key type, so a repeated name
// risks the update being rejected over configuration the user was entitled to write.
func TestDuplicateCertificateNameIsEmittedOnce(t *testing.T) {
	const sharedIdentifier = "arn:aws:acm:us-east-1:123456789012:certificate/shared"

	tests := []struct {
		name        string
		tlsConfig   *ir.TLSConfig
		resolutions map[string]*tlsv3.SdsSecretConfig
		wantNames   []string
	}{
		{
			// The case that motivated this: two resources, one underlying certificate.
			name: "two distinct resources resolving to one identifier",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				extensionRefCert("cert-alpha"),
				extensionRefCert("cert-beta"),
			}},
			resolutions: map[string]*tlsv3.SdsSecretConfig{
				"cert-alpha": {Name: sharedIdentifier},
				"cert-beta":  {Name: sharedIdentifier},
			},
			wantNames: []string{sharedIdentifier},
		},
		{
			name: "the same certificateRef listed twice",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				extensionRefCert("ext-cert"),
				extensionRefCert("ext-cert"),
			}},
			resolutions: map[string]*tlsv3.SdsSecretConfig{"ext-cert": {Name: sharedIdentifier}},
			wantNames:   []string{sharedIdentifier},
		},
		{
			name: "the same Secret listed twice",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				{Name: "default/tls-secret", Certificate: []byte("cert"), PrivateKey: []byte("key")},
				{Name: "default/tls-secret", Certificate: []byte("cert"), PrivateKey: []byte("key")},
			}},
			wantNames: []string{"default/tls-secret"},
		},
		{
			// The RSA plus ECDSA case must keep working: dedupe must not collapse
			// certificates that genuinely differ.
			name: "two identifiers that differ are both emitted",
			tlsConfig: &ir.TLSConfig{Certificates: []ir.TLSCertificate{
				extensionRefCert("cert-rsa"),
				extensionRefCert("cert-ecdsa"),
			}},
			resolutions: map[string]*tlsv3.SdsSecretConfig{
				"cert-rsa":   {Name: "arn:aws:acm:us-east-1:123456789012:certificate/rsa"},
				"cert-ecdsa": {Name: "arn:aws:acm:us-east-1:123456789012:certificate/ecdsa"},
			},
			wantNames: []string{
				"arn:aws:acm:us-east-1:123456789012:certificate/rsa",
				"arn:aws:acm:us-east-1:123456789012:certificate/ecdsa",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tSocket, err := buildXdsDownstreamTLSSocket(tc.tlsConfig, tc.resolutions)
			require.NoError(t, err)

			tlsCtx := &tlsv3.DownstreamTlsContext{}
			require.NoError(t, tSocket.GetTypedConfig().UnmarshalTo(tlsCtx))

			var names []string
			for _, c := range tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
				names = append(names, c.GetName())
			}
			require.Equal(t, tc.wantNames, names)
		})
	}
}

// The QUIC socket builds its certificate list from the same helper, so it must dedupe too.
// Asserted separately because the two builders were duplicated before and drifting apart would
// mean HTTP/3 listeners silently keeping the behaviour this fixes.
func TestQUICDeduplicatesCertificateNames(t *testing.T) {
	const sharedIdentifier = "arn:aws:acm:us-east-1:123456789012:certificate/shared"

	tlsConfig := &ir.TLSConfig{Certificates: []ir.TLSCertificate{
		extensionRefCert("cert-alpha"),
		extensionRefCert("cert-beta"),
	}}
	resolutions := map[string]*tlsv3.SdsSecretConfig{
		"cert-alpha": {Name: sharedIdentifier},
		"cert-beta":  {Name: sharedIdentifier},
	}

	tSocket, err := buildDownstreamQUICTransportSocket(tlsConfig, resolutions)
	require.NoError(t, err)

	quicCtx := &quicv3.QuicDownstreamTransport{}
	require.NoError(t, tSocket.GetTypedConfig().UnmarshalTo(quicCtx))

	configs := quicCtx.GetDownstreamTlsContext().GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	require.Len(t, configs, 1)
	require.Equal(t, sharedIdentifier, configs[0].GetName())
	require.Nil(t, configs[0].GetSdsConfig())
}
