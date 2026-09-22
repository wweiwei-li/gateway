// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package main implements an extension server that resolves Gateway listener TLS
// certificates from a custom resource, using the TLSCertificate hook.
//
// It stands in for a provider whose data plane holds the certificate itself and resolves a
// secret name internally -- for example a hosted certificate service, an HSM-backed CA, or a
// data plane with its own certificate store. For such a provider the entire xDS contribution is
// a name on the filter chain:
//
//	tls_certificate_sds_secret_configs:
//	- name: "<identifier>"
//
// with no sds_config, because there is nothing for Envoy to connect to. Envoy Gateway emits no
// Secret for these certificates, so no key material passes through the control plane.
//
// Readiness is reported on the custom resource rather than through this hook. Envoy Gateway
// reads status.conditions[type=Ready] during admission and only calls the hook once the
// certificate is ready, which is why this handler has no notion of pending.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/envoyproxy/gateway/proto/extension"
)

// certificateServer resolves listener certificates. It embeds the unimplemented server so the
// hooks it does not handle are rejected rather than silently succeeding.
type certificateServer struct {
	extension.UnimplementedEnvoyGatewayExtensionServer

	// identifierField is the path within the resource's spec holding the identifier the data
	// plane knows the certificate by, expressed as a JSON field name.
	identifierField string

	// refuse, when set, makes every resolution return this as the FailureReason instead of an
	// identifier. It models a provider whose certificate is not yet usable, so the listener
	// fails closed. Left empty in normal operation.
	refuse string

	// stampIdentifier, when set, is returned verbatim as the identifier regardless of the
	// resource's spec. It exists so a caller can prove the hook result is what reaches the
	// filter chain, rather than a value Envoy Gateway derived some other way.
	stampIdentifier string

	// quiet suppresses per-resolution logging, for tests that drive many translations.
	quiet bool
}

// PostTLSCertificateResolve tells Envoy Gateway how to reference one listener certificate.
//
// The handler is intentionally a pure function of the request. Envoy Gateway calls it on every
// translation cycle behind a timeout, so it must not perform I/O: a blocking call here stalls
// translation for every Gateway in the cluster. A real provider keeps a cache maintained by a
// separate reconciler and reads only that.
//
// It must also be deterministic. A different answer for identical input produces a new xDS
// snapshot version on every cycle, which Envoy Gateway cannot detect and which results in
// continuous pushes to every proxy.
func (s *certificateServer) PostTLSCertificateResolve(
	_ context.Context,
	req *extension.PostTLSCertificateResolveRequest,
) (*extension.PostTLSCertificateResolveResponse, error) {
	certCtx := req.GetPostTlsCertificateContext()
	if certCtx == nil {
		return nil, fmt.Errorf("request carried no certificate context")
	}

	obj, err := decodeResource(certCtx.GetCertificateResource())
	if err != nil {
		return nil, err
	}

	// A provider that cannot yet serve the certificate returns a failure reason. Envoy Gateway
	// omits the certificate, so the listener fails closed rather than referencing something the
	// data plane does not have.
	if s.refuse != "" {
		return &extension.PostTLSCertificateResolveResponse{
			FailureReason:  s.refuse,
			FailureMessage: fmt.Sprintf("%s/%s is not yet usable", obj.GetNamespace(), obj.GetName()),
		}, nil
	}

	identifier := s.stampIdentifier
	if identifier == "" {
		var found bool
		identifier, found, err = unstructured.NestedString(obj.Object, "spec", s.identifierField)
		if err != nil {
			return nil, fmt.Errorf("reading spec.%s of %s/%s: %w",
				s.identifierField, obj.GetNamespace(), obj.GetName(), err)
		}
		if !found || identifier == "" {
			// Reported as a resolution failure rather than a gRPC error: the reference is
			// structurally fine, the resource is simply not usable. Envoy Gateway treats the
			// certificate as unresolved and omits it, so the listener fails closed.
			return &extension.PostTLSCertificateResolveResponse{
				FailureReason: "MissingIdentifier",
				FailureMessage: fmt.Sprintf("%s/%s has no spec.%s",
					obj.GetNamespace(), obj.GetName(), s.identifierField),
			}, nil
		}
	}

	if !s.quiet {
		log.Printf("resolved certificate %s/%s for %s/%s listener %q -> %q",
			obj.GetNamespace(), obj.GetName(),
			certCtx.GetGatewayNamespace(), certCtx.GetGatewayName(), certCtx.GetListenerName(),
			identifier)
	}

	return &extension.PostTLSCertificateResolveResponse{
		// No SdsConfig: the data plane resolves this name from its own certificate store.
		// Envoy Gateway passes the nil through rather than substituting a config source, so
		// the filter chain carries the name alone.
		SdsSecretConfig: &tlsv3.SdsSecretConfig{Name: identifier},

		// Deliberately empty. Populating Clusters would ask Envoy Gateway to add a cluster for
		// a network-reached provider, and Secrets would place key material in the xDS stream.
		// Neither applies here.
	}, nil
}

func decodeResource(res *extension.ExtensionResource) (*unstructured.Unstructured, error) {
	if res == nil || len(res.GetUnstructuredBytes()) == 0 {
		return nil, fmt.Errorf("request carried no certificate resource")
	}

	var obj unstructured.Unstructured
	if err := json.Unmarshal(res.GetUnstructuredBytes(), &obj.Object); err != nil {
		return nil, fmt.Errorf("unmarshalling certificate resource: %w", err)
	}
	return &obj, nil
}

func main() {
	var (
		addr            = flag.String("address", ":5005", "address to serve on; a path is treated as a unix socket")
		socket          = flag.String("socket", "", "unix socket path to serve on; overrides --address when set")
		identifierField = flag.String("identifier-field", "certificateArn",
			"field under spec holding the identifier the data plane knows the certificate by")
		refuse = flag.String("refuse", "",
			"when set, refuse every resolution with this reason, modelling a not-yet-usable certificate")
		stampIdentifier = flag.String("stamp-identifier", "",
			"when set, return this identifier verbatim regardless of the resource spec")
		quiet = flag.Bool("quiet", false, "suppress per-resolution logging")
	)
	flag.Parse()

	network, address := "tcp", *addr
	if *socket != "" {
		address = *socket
	}
	if len(address) > 0 && address[0] == '/' {
		// A unix socket keeps the server unreachable over the network, which suits running it
		// as a sidecar of the Envoy Gateway pod.
		network = "unix"
		if err := os.Remove(address); err != nil && !os.IsNotExist(err) {
			log.Fatalf("removing stale socket %s: %v", address, err)
		}
	}

	lis, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("listening on %s %s: %v", network, address, err)
	}

	srv := grpc.NewServer()
	extension.RegisterEnvoyGatewayExtensionServer(srv, &certificateServer{
		identifierField: *identifierField,
		refuse:          *refuse,
		stampIdentifier: *stampIdentifier,
		quiet:           *quiet,
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("shutting down")
		srv.GracefulStop()
	}()

	log.Printf("certificate extension server listening on %s %s, reading spec.%s", network, address, *identifierField)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serving: %v", err)
	}
}
