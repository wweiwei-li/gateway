// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Command validate-eg-config decodes an EnvoyGateway config out of a ConfigMap and runs it
// through Envoy Gateway's own decoder and validation, so a hand-written ConfigMap is checked
// against the real API rather than by eye.
//
// Usage: go run ./hack/validate-eg-config <configmap.yaml>
package main

import (
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/envoyproxy/gateway/api/v1alpha1/validation"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-eg-config <configmap.yaml>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshalling ConfigMap: %v\n", err)
		os.Exit(1)
	}

	body, ok := cm.Data["envoy-gateway.yaml"]
	if !ok {
		fmt.Fprintln(os.Stderr, "ConfigMap has no data[\"envoy-gateway.yaml\"]")
		os.Exit(1)
	}

	tmp, err := os.CreateTemp("", "eg-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temp file: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		fmt.Fprintf(os.Stderr, "writing temp file: %v\n", err)
		os.Exit(1)
	}
	_ = tmp.Close()

	eg, err := config.Decode(tmp.Name())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL decode: %v\n", err)
		os.Exit(1)
	}

	if err := validation.ValidateEnvoyGateway(eg); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL validation: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("decode and validation OK")

	for _, em := range eg.GetExtensionManagers() {
		fmt.Printf("extension manager %q failOpen=%v\n", em.Name, em.FailOpen)
		for _, gvk := range em.CertificateResources {
			fmt.Printf("  certificate kind: %s/%s %s\n", gvk.Group, gvk.Version, gvk.Kind)
		}
		if em.Hooks != nil && em.Hooks.XDSTranslator != nil {
			fmt.Printf("  post hooks: %v\n", em.Hooks.XDSTranslator.Post)
		}
		if em.Service != nil && em.Service.Unix != nil {
			fmt.Printf("  extension socket: %s\n", em.Service.Unix.Path)
		}
	}

	if p := eg.Provider; p != nil && p.Custom != nil && p.Custom.Infrastructure != nil &&
		p.Custom.Infrastructure.Remote != nil && p.Custom.Infrastructure.Remote.Service != nil &&
		p.Custom.Infrastructure.Remote.Service.Unix != nil {
		fmt.Printf("  infra socket:     %s\n", p.Custom.Infrastructure.Remote.Service.Unix.Path)
	}
}
