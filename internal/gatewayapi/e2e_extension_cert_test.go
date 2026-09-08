// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build e2eextcert

// End-to-end proof that a Gateway listener can serve a certificate held by an external
// provider, exercising both halves of the design against each other:
//
//   - Envoy Gateway: this package's real translation path, driven from Gateway API YAML.
//   - The provider: the AWS managed proxy controller's real extension server, run as a
//     subprocess over a Unix socket. Not a stub -- the same handler that ships.
//
// The assertion is on the xDS Envoy Gateway emits: the filter chain must reference the
// provider's identifier with no SdsConfig, and no Secret resource may appear anywhere.
//
// Run with:
//
//	go test -tags e2eextcert ./internal/gatewayapi/ -run TestE2E -v
//
// The controller repository is located via MANAGED_PROXY_REPO, defaulting to a sibling
// checkout. The test skips if it is absent.
package gatewayapi

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	"github.com/envoyproxy/gateway/internal/extension/registry"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/xds/translator"
	xdstypes "github.com/envoyproxy/gateway/internal/xds/types"
)

const (
	e2eCertGroup = "gateway.managedproxy.aws"
	e2eCertKind  = "AWSManagedCertificate"
	e2eCertARN   = "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"
)

// e2eResources is what a customer writes: a Gateway whose HTTPS listener references a
// certificate resource by group and kind, and the certificate itself reporting ready.
const e2eResources = `
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: eg
  namespace: default
spec:
  gatewayClassName: eg
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: www.example.com
    tls:
      mode: Terminate
      certificateRefs:
      - group: gateway.managedproxy.aws
        kind: AWSManagedCertificate
        name: app-cert
---
apiVersion: gateway.managedproxy.aws/v1alpha1
kind: AWSManagedCertificate
metadata:
  name: app-cert
  namespace: default
spec:
  certificateARN: arn:aws:acm:us-east-1:123456789012:certificate/abc-123
status:
  conditions:
  - type: Ready
    status: "True"
    reason: Associated
    message: certificate is available on the data plane
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: backend
  namespace: default
spec:
  parentRefs:
  - name: eg
  hostnames:
  - www.example.com
  rules:
  - backendRefs:
    - name: backend
      port: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: default
spec:
  ports:
  - port: 3000
    targetPort: 3000
---
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: envoy
  namespace: envoy-gateway-system
data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURBVENDQWVtZ0F3SUJBZ0lVZEEwZytoaG5UZzQwS0xkMHRuMDk3WDNqMlVnd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0VERU9NQXdHQTFVRUF3d0ZaVzUyYjNrd0hoY05Nall3T1RBeU1qRXlOekkzV2hjTk16WXdPRE13TWpFeQpOekkzV2pBUU1RNHdEQVlEVlFRRERBVmxiblp2ZVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDCkFRb0NnZ0VCQU1SdDQ5eUZUTU5jQkNuQ1lPc2dGd05hRkcvWmsvU2hwUmRUdHl6SjhHc0dCOXZaQUNMSW52dGsKVEdmeHpmWFRpdk1wTlF5YUJvSEorNWliTkUxRTRKcGc3SFRmeXdxeVUvdWt4S0xPSlFaeU92dHVncUlaR0c0Mgp5ekpyQVJHOXkrcjE3YWlLemhUYUNxYUJyNnc0MUxBdU5tYXlNZGpDUmVDVGpmL1BudjA0dm5xVmpHdFZKQVU3CmJ1alNjWVFxT0U0dUQ3ZlYyN0dRUTJXRk01MTVtYlFLc0FOSXVNUFYveW1XaktQNERjUmRkY3FQT2h5YjhzaGwKWkhPRHJKVC9hZmFUU0lwVFlLeGcrNWJWOGFRNXR3YzFrQ1ZhVFJLN1BKQ1RDUGx6eVdJZldsZHMrWkRPcnVtSQpKQ0FpUHcyZ0ovWnlLT3ZUUDhnMnE5NDd6a2VWaFgwQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZKYytVM1BDCmNxMUtoMGk0dTJlR0x4NHB3aFROTUI4R0ExVWRJd1FZTUJhQUZKYytVM1BDY3ExS2gwaTR1MmVHTHg0cHdoVE4KTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtFdVhqUks0R0FYd1Zxawp5c0Ezd3pNakVMZW1xdTd1S09qR2taQTF0bm1NZjQwMEVXV0J3eGQxZVpIVXNkdUxneGdrRUVLYXFmTXNnUG5NClFxSjVuS21kZFpaMnFJcDZnVlVLYllCRzA5K0RvRGNXeFZhOEdoeVZOZ2tlKzR2ZUVuaTFTRUNnSmJLbjRCTHAKUzlvTDQrR1BwUk45MERGT3hmU0paV1NwZTFDVlVGajA2WGNaL2JQbmhxVUpQb211d2JiYml0azlTM3ZzdkRlMgppVnRoOEgvWEdVQlB4QUdweXA3cGNnV0lKSHhYS1Q3VTQyRXYrMU1CZmIxelNIQ21RUUY5WjBvYnRnd2l3dzZjCnl5bnZrTjRPc1V0ZS9Pa1I5aE5vdzNydHFnZFdmWldlaDRJam5tQ1RKeFMrY1NVSGl4ZlRuZUg4TjJRR2tueG0KMDRTRzU1az0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURBVENDQWVtZ0F3SUJBZ0lVZEEwZytoaG5UZzQwS0xkMHRuMDk3WDNqMlVnd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0VERU9NQXdHQTFVRUF3d0ZaVzUyYjNrd0hoY05Nall3T1RBeU1qRXlOekkzV2hjTk16WXdPRE13TWpFeQpOekkzV2pBUU1RNHdEQVlEVlFRRERBVmxiblp2ZVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDCkFRb0NnZ0VCQU1SdDQ5eUZUTU5jQkNuQ1lPc2dGd05hRkcvWmsvU2hwUmRUdHl6SjhHc0dCOXZaQUNMSW52dGsKVEdmeHpmWFRpdk1wTlF5YUJvSEorNWliTkUxRTRKcGc3SFRmeXdxeVUvdWt4S0xPSlFaeU92dHVncUlaR0c0Mgp5ekpyQVJHOXkrcjE3YWlLemhUYUNxYUJyNnc0MUxBdU5tYXlNZGpDUmVDVGpmL1BudjA0dm5xVmpHdFZKQVU3CmJ1alNjWVFxT0U0dUQ3ZlYyN0dRUTJXRk01MTVtYlFLc0FOSXVNUFYveW1XaktQNERjUmRkY3FQT2h5YjhzaGwKWkhPRHJKVC9hZmFUU0lwVFlLeGcrNWJWOGFRNXR3YzFrQ1ZhVFJLN1BKQ1RDUGx6eVdJZldsZHMrWkRPcnVtSQpKQ0FpUHcyZ0ovWnlLT3ZUUDhnMnE5NDd6a2VWaFgwQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZKYytVM1BDCmNxMUtoMGk0dTJlR0x4NHB3aFROTUI4R0ExVWRJd1FZTUJhQUZKYytVM1BDY3ExS2gwaTR1MmVHTHg0cHdoVE4KTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtFdVhqUks0R0FYd1Zxawp5c0Ezd3pNakVMZW1xdTd1S09qR2taQTF0bm1NZjQwMEVXV0J3eGQxZVpIVXNkdUxneGdrRUVLYXFmTXNnUG5NClFxSjVuS21kZFpaMnFJcDZnVlVLYllCRzA5K0RvRGNXeFZhOEdoeVZOZ2tlKzR2ZUVuaTFTRUNnSmJLbjRCTHAKUzlvTDQrR1BwUk45MERGT3hmU0paV1NwZTFDVlVGajA2WGNaL2JQbmhxVUpQb211d2JiYml0azlTM3ZzdkRlMgppVnRoOEgvWEdVQlB4QUdweXA3cGNnV0lKSHhYS1Q3VTQyRXYrMU1CZmIxelNIQ21RUUY5WjBvYnRnd2l3dzZjCnl5bnZrTjRPc1V0ZS9Pa1I5aE5vdzNydHFnZFdmWldlaDRJam5tQ1RKeFMrY1NVSGl4ZlRuZUg4TjJRR2tueG0KMDRTRzU1az0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRREViZVBjaFV6RFhBUXAKd21EcklCY0RXaFJ2MlpQMG9hVVhVN2NzeWZCckJnZmIyUUFpeUo3N1pFeG44YzMxMDRyektUVU1tZ2FCeWZ1WQptelJOUk9DYVlPeDAzOHNLc2xQN3BNU2l6aVVHY2pyN2JvS2lHUmh1TnNzeWF3RVJ2Y3ZxOWUyb2lzNFUyZ3FtCmdhK3NPTlN3TGpabXNqSFl3a1hnazQzL3o1NzlPTDU2bFl4clZTUUZPMjdvMG5HRUtqaE9MZyszMWR1eGtFTmwKaFRPZGVabTBDckFEU0xqRDFmOHBsb3lqK0EzRVhYWEtqem9jbS9MSVpXUnpnNnlVLzJuMmswaUtVMkNzWVB1VwoxZkdrT2JjSE5aQWxXazBTdXp5UWt3ajVjOGxpSDFwWGJQbVF6cTdwaUNRZ0lqOE5vQ2YyY2lqcjB6L0lOcXZlCk84NUhsWVY5QWdNQkFBRUNnZ0VBQ3lkNFZIbm5VWUtrbytCclUzNjNmOU82TEYzTkZvdWxUYzFOcmdmcmxKQTcKbXdMWURLR2EwWWl4QkFnSm00ZC9NTzZxbWdRWEVZQ3dQa3ExN2h0V3E3Mk1QOWpEZFdDSi8xU3NhOWhMNXZGTwpveDl6NEpPUFBSYjBjL0Q2bHhEUmh3NmZCNzZXRkQ0TGM4Z1Nlek9nOUQ0emphSlp6VWErNUJGTTgzVk5RSERDCmJ0Uk1yTlI3MnNwUlkvYTkybkErLzJFRnBxekNTQTFaM1lNQ1ZobC9HN09IU2EyNzNwOHM3a012UWxPR1lSUzgKN21Qd3RXdmVqV1loTm9OblBIbDlvOEVXVDRKdG53UEJnQXJhV3k4bDh4YXJIdzdKVlN5VVNGS09qTmQ5Z0U5cApORDhoOVpDaVJNNzBhbFZKelluVFNwV0lVS1l1d3ZoM1hDcXRPdVdzZXdLQmdRRHZQcE43amJSRFZoRFgveDZaCnFLMk9yUU56YXRoT2VrbXBGQkRiZVNHQmZIck0rWWVSTCt1S0VnSEk2MXZ5SHAycUpaaHdISUtlT2dhbXYvVXcKRkFqRGpKZzNzMGRZWWpCcExETWlBQWR2UXYzckZXU0ZzOUJ1U1ZVL0pCSFA5bnV5akhUcW44aTJkVHM4TGFMVgpVSjI2bmNZamZESmp6Z2t1QngrZW1IdzJqd0tCZ1FEU0w2M0Rtek9HTEQrR0FYWE93OGc3ZEdJV1VkaW1La1AxCnlJRFhEUklFcXM4MVZKaVF4RTVlMTg0cStTNytaNWNBbzBtYTBnRXYzM1hZdWM3MWxPV1ZHTG1LRXljT3dvdWQKSUk5UTlvbC9CY1AreUZ0SkFkbmk5TTdvbHVKNzIramtIRUZGUllaWDFibXVZcE45ZmlsVzI4TXRBd3RaL1RCUwoxblErYnlwcE13S0JnUUNUMjNHY2YyUXo1V0g5aTk4bWlmZlJZSjNzVzlFWkZ6eWs4UkRHQXlPdytmU083M3hZClAyeHJaVnVUQjlwSVZhR05RVFRudk1jQThNMmhpcXNHcnFzSDU4RS9VMTQ1Z2wxMjhta2JqemNKRFRjT2JhYzEKZG43UFdpVUVJOCthWGpQdWtoM0R6MEpsZVNoRnRkS1gwUDNhRXA0YzJpbnVRcXlydEoxWEQ5aGNnd0tCZ0VqaAoyWW9iVmdsdmJIT0dMQmlQVU80MDFCSlRQU0daUkVtRXhoQkw2dlNOV2g1dkFCd3F4ZFlqVk0wWDdOQ3drTzdhCnNCb3NPZGNrMEZOZlVzRmJhU1NERjBzbWl3T1dPQjA2L2hjZjlkdUMzMHlJb3dhMHlwM2xMNTM5Ty9tZzdxZXkKbUh0eHVUelowbklDb293QVpFdEhGdTJUd2FycG5Za0w3ZkQ4VVNON0FvR0FWdGZSNGYrSkJDWVlrYStRV3BXMApPeFQ4MVdOZ2RqUnk1cStXcHZvVDM5QUo2OW5rQ3QwTE1EVGtkYVZaUnRYZmhCMDk3ZUhpS09BWWNJSXo4K2dkClRDem5RUjk1Qmk5NmJzRjBzM0Nzd1VSalBISW9LSVRmVjNsQW8yWTRMeTNOZlo4bmRVRjdZVVFHMjd5aW5GWDAKNldoUzNuYTN0Q2NhMWZpWkNEVE5WcUE9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K
`

// startProviderExtensionServer builds and runs the controller's extension server, returning its
// socket path. Building from source rather than vendoring a stub is the point: the handler under
// test is the one that ships.
func startProviderExtensionServer(t *testing.T, extraArgs ...string) string {
	t.Helper()

	repo := os.Getenv("MANAGED_PROXY_REPO")
	if repo == "" {
		wd, err := os.Getwd()
		require.NoError(t, err)
		repo = filepath.Join(wd, "..", "..", "..", "sigs.k8s.io", "aws-managed-proxy-for-envoy-gateway")
	}
	if _, err := os.Stat(filepath.Join(repo, "cmd", "extension-server")); err != nil {
		t.Skipf("controller repo not found at %s; set MANAGED_PROXY_REPO", repo)
	}

	bin := filepath.Join(t.TempDir(), "extension-server")
	build := exec.Command("go", "build", "-o", bin, "./cmd/extension-server")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building extension server: %v\n%s", err, out)
	}

	// Not t.TempDir(): macOS caps unix socket paths near 104 bytes and the per-test temp
	// directory is long enough to exceed it.
	socket := filepath.Join(os.TempDir(), fmt.Sprintf("e2e-ext-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socket) })

	args := append([]string{"--socket", socket, "--quiet"}, extraArgs...)
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", socket)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, 30*time.Second, 50*time.Millisecond, "extension server did not start on %s", socket)

	return socket
}

// translateWithProvider runs the real Gateway API and xDS translation with the extension manager
// pointed at the provider's socket, exactly as a configured Envoy Gateway would.
func translateWithProvider(t *testing.T, socket string) (*xdstypes.ResourceVersionTable, *resource.Resources, []*gwapiv1.Gateway) {
	t.Helper()
	return translateResourcesWithProvider(t, socket, e2eResources)
}

// translateResourcesWithProvider is translateWithProvider over caller-supplied resources, so a
// test can vary what the customer wrote -- notably the certificate's readiness.
func translateResourcesWithProvider(t *testing.T, socket, yamlDoc string) (*xdstypes.ResourceVersionTable, *resource.Resources, []*gwapiv1.Gateway) {
	t.Helper()

	extMgrCfg := egv1a1.ExtensionManager{
		CertificateResources: []egv1a1.GroupVersionKind{
			{Group: e2eCertGroup, Version: "v1alpha1", Kind: e2eCertKind},
		},
		Hooks: &egv1a1.ExtensionHooks{
			XDSTranslator: &egv1a1.XDSTranslatorHooks{
				Post: []egv1a1.XDSTranslatorHook{egv1a1.XDSTLSCertificate},
			},
		},
		Service: &egv1a1.ExtensionService{
			BackendEndpoint: egv1a1.BackendEndpoint{
				Unix: &egv1a1.UnixSocket{Path: socket},
			},
		},
	}

	eg := egv1a1.DefaultEnvoyGateway()
	eg.ExtensionManager = &extMgrCfg

	// The loader needs the extension manager registered to classify the certificate resource,
	// which is the same path the File provider uses.
	res, err := resource.LoadResourcesFromYAMLBytes([]byte(yamlDoc), true, eg)
	require.NoError(t, err)
	require.Len(t, res.ExtensionCertificates, 1, "certificate resource should have been loaded")

	extMgr, err := registry.NewManager(&config.Server{
		EnvoyGateway:        eg,
		ControllerNamespace: "envoy-gateway-system",
		Logger:              logging.DefaultLogger(os.Stderr, egv1a1.LogLevelError),
	}, false)
	require.NoError(t, err)
	t.Cleanup(extMgr.CleanupHookConns)

	gwTranslator := &Translator{
		GatewayControllerName: string(res.GatewayClass.Spec.ControllerName),
		GatewayClassName:      gwapiv1.ObjectName(res.GatewayClass.Name),
		ControllerNamespace:   "envoy-gateway-system",
		ExtensionCertificateGroupKinds: []schema.GroupKind{
			{Group: e2eCertGroup, Kind: e2eCertKind},
		},
	}

	result, err := gwTranslator.Translate(t.Context(), res)
	require.NoError(t, err)

	xdsTranslator := &translator.Translator{
		ControllerNamespace: "envoy-gateway-system",
		ExtensionManager:    &extMgr,
	}

	var tCtx *xdstypes.ResourceVersionTable
	for key, xdsIR := range result.XdsIR {
		tCtx, err = xdsTranslator.Translate(t.Context(), xdsIR)
		require.NoError(t, err, "xds translation failed for %s", key)
		break
	}
	require.NotNil(t, tCtx, "no xDS produced")

	return tCtx, res, result.Gateways
}

// The customer's configuration must produce a filter chain naming the provider's identifier and
// nothing else: no config source to fetch from, and no Secret carrying key material.
func TestE2EExtensionCertificateEmitsIdentifierOnly(t *testing.T) {
	socket := startProviderExtensionServer(t)
	tCtx, _, gateways := translateWithProvider(t, socket)

	// The listener must actually be programmed.
	require.Len(t, gateways, 1)
	var programmed bool
	for _, l := range gateways[0].Status.Listeners {
		if l.Name != "https" {
			continue
		}
		for _, c := range l.Conditions {
			if c.Type == string(gwapiv1.ListenerConditionProgrammed) {
				programmed = c.Status == "True"
				t.Logf("listener https: Programmed=%s reason=%s", c.Status, c.Reason)
			}
		}
	}
	require.True(t, programmed, "listener should be programmed when the certificate is ready")

	// No Secret resource may be emitted for the certificate.
	for _, r := range tCtx.XdsResources[resourcev3.SecretType] {
		secret, ok := r.(*tlsv3.Secret)
		require.True(t, ok)
		require.NotEqual(t, e2eCertARN, secret.GetName(),
			"Envoy Gateway must not emit a Secret for an externally provided certificate")
	}

	// The filter chain must carry the identifier alone.
	found := forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() != e2eCertARN {
				continue
			}
			require.Nil(t, sc.GetSdsConfig(),
				"identifier must be emitted with no SdsConfig; the data plane resolves it locally")
			t.Logf("filter chain references %q with no sds_config", sc.GetName())
			return true
		}
		return false
	})
	require.True(t, found, "no filter chain referenced %s", e2eCertARN)
}

// When the provider refuses -- a certificate still propagating -- Envoy Gateway must omit it
// rather than emit a dangling reference, so the listener fails closed.
func TestE2EExtensionCertificateFailsClosedOnRefusal(t *testing.T) {
	socket := startProviderExtensionServer(t, "--refuse", "AssociationInProgress")
	tCtx, _, _ := translateWithProvider(t, socket)

	referenced := forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() == e2eCertARN {
				return true
			}
		}
		return false
	})
	require.False(t, referenced,
		"a refused certificate must not be referenced; the listener must fail closed instead")
}

// forEachDownstreamTLSContext unmarshals every listener filter chain's transport socket and
// applies fn, reporting whether any returned true.
func forEachDownstreamTLSContext(t *testing.T, tCtx *xdstypes.ResourceVersionTable, fn func(*tlsv3.DownstreamTlsContext) bool) bool {
	t.Helper()

	var matched bool
	for _, r := range tCtx.XdsResources[resourcev3.ListenerType] {
		l, ok := r.(*listenerv3.Listener)
		if !ok {
			continue
		}
		for _, fc := range l.GetFilterChains() {
			ts := fc.GetTransportSocket()
			if ts == nil || ts.GetTypedConfig() == nil {
				continue
			}
			var ctx tlsv3.DownstreamTlsContext
			if err := ts.GetTypedConfig().UnmarshalTo(&ctx); err != nil {
				continue
			}
			if fn(&ctx) {
				matched = true
			}
		}
	}
	return matched
}

// Proof that the hook is genuinely consulted, rather than the identifier being derived from the
// resource by Envoy Gateway some other way.
//
// The provider is told to return a value that appears nowhere in the customer's configuration.
// Envoy Gateway has no source for it: it never reads spec.certificateARN, and all it holds is
// the IR name "group/Kind/namespace/name". So if this value reaches the filter chain, it
// travelled over gRPC from the extension server and was used verbatim.
func TestE2EExtensionCertificateIdentifierComesFromProvider(t *testing.T) {
	const stamped = "provider-supplied-identifier-not-in-any-manifest"

	socket := startProviderExtensionServer(t, "--stamp-identifier", stamped)
	tCtx, _, _ := translateWithProvider(t, socket)

	found := forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() == stamped {
				require.Nil(t, sc.GetSdsConfig())
				t.Logf("filter chain carries the provider's value %q", sc.GetName())
				return true
			}
		}
		return false
	})
	require.True(t, found,
		"the provider's identifier did not reach the xDS, so the hook result was not used")

	// And the ARN from the manifest must be absent, confirming Envoy Gateway did not fall back
	// to reading the resource itself.
	usedARN := forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() == e2eCertARN {
				return true
			}
		}
		return false
	})
	require.False(t, usedARN, "Envoy Gateway must take the identifier from the hook, not the spec")
}

// The pending experience and its recovery, which is what the user experience doc promises: a
// certificate that is not yet ready leaves the listener out of the configuration entirely rather
// than emitting it broken, and the listener comes up once the provider reports it ready with no
// change to anything the customer wrote.
//
// This covers three things the other tests do not, because they all start from Ready=True:
//
//   - a pending certificate produces no filter chain at all, so the port is not listening and a
//     client is refused rather than meeting a listener that cannot complete a handshake
//   - the listener reports CertificatePending, distinguishable from a broken reference
//   - flipping Ready is by itself sufficient to program the listener
//
// What this does not cover is the watch: at translation level the retranslation is invoked
// directly, so it does not exercise certificateResourcePredicates omitting the
// generation-changed predicate. That needs a controller-level test against a real API server.
func TestE2EExtensionCertificatePendingThenReady(t *testing.T) {
	socket := startProviderExtensionServer(t)

	pending := strings.NewReplacer(
		`status: "True"`, `status: "False"`,
		"reason: Associated", "reason: AssociationInProgress",
	).Replace(e2eResources)
	require.Contains(t, pending, `status: "False"`, "fixture rewrite did not take effect")
	require.Contains(t, pending, "reason: AssociationInProgress", "fixture rewrite did not take effect")

	// Phase 1: the certificate is not ready. The configuration is valid, so the listener is
	// accepted -- but it must not be programmed, and nothing for it may reach the data plane.
	tCtx, _, gateways := translateResourcesWithProvider(t, socket, pending)

	acceptedStatus, _ := listenerCondition(t, gateways, "https", gwapiv1.ListenerConditionAccepted)
	require.Equal(t, "True", acceptedStatus,
		"the customer's configuration is valid, so the listener is accepted")

	programmedStatus, programmedReason := listenerCondition(t, gateways, "https", gwapiv1.ListenerConditionProgrammed)
	require.Equal(t, "False", programmedStatus, "a pending certificate must not program the listener")
	require.Equal(t, "CertificatePending", programmedReason,
		"pending must be reported distinctly from an invalid certificate reference")

	referenced := forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() == e2eCertARN {
				return true
			}
		}
		return false
	})
	require.False(t, referenced,
		"a pending certificate must not appear in the configuration sent to the proxy")
	t.Logf("pending: Accepted=True, Programmed=False reason=%s, nothing emitted for the certificate",
		programmedReason)

	// Phase 2: the provider reports the certificate ready. Nothing the customer wrote changed.
	tCtx, _, gateways = translateResourcesWithProvider(t, socket, e2eResources)

	programmedStatus, programmedReason = listenerCondition(t, gateways, "https", gwapiv1.ListenerConditionProgrammed)
	require.Equal(t, "True", programmedStatus,
		"the listener must be programmed once the certificate reports ready")

	referenced = forEachDownstreamTLSContext(t, tCtx, func(ctx *tlsv3.DownstreamTlsContext) bool {
		for _, sc := range ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
			if sc.GetName() != e2eCertARN {
				continue
			}
			require.Nil(t, sc.GetSdsConfig(),
				"identifier must still be emitted with no SdsConfig after recovery")
			return true
		}
		return false
	})
	require.True(t, referenced, "the identifier must reach the filter chain once the certificate is ready")
	t.Logf("ready: Programmed=True reason=%s, filter chain references %s", programmedReason, e2eCertARN)
}

// listenerCondition returns the status and reason of one condition on a named listener, failing
// the test if the listener or condition is absent.
func listenerCondition(t *testing.T, gateways []*gwapiv1.Gateway, name string, condType gwapiv1.ListenerConditionType) (status, reason string) {
	t.Helper()
	require.Len(t, gateways, 1, "expected exactly one Gateway")
	for _, l := range gateways[0].Status.Listeners {
		if string(l.Name) != name {
			continue
		}
		for _, c := range l.Conditions {
			if c.Type == string(condType) {
				return string(c.Status), c.Reason
			}
		}
	}
	t.Fatalf("listener %q has no %s condition", name, condType)
	return "", ""
}
