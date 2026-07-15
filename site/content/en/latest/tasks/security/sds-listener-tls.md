---
title: "TLS Termination with External SDS Server"
---

## Overview

This task shows how to configure a Gateway listener to fetch TLS certificates from an external
Secret Discovery Service (SDS) server instead of storing them in Kubernetes Secrets.

This is useful when:

- Certificates are managed by an external system (e.g., AWS ACM, HashiCorp Vault)
- A sidecar agent (e.g., SPIRE, ACM agent) runs in the data plane and serves certificates over a Unix Domain Socket
- You want certificate rotation handled outside of Kubernetes

## Architecture

```
┌────────────────────── Data Plane Pod ──────────────────────┐
│                                                             │
│  ┌──────────────┐     gRPC (UDS)     ┌──────────────────┐  │
│  │    Envoy     │ ◄────────────────► │   SDS Server     │  │
│  │    Proxy     │                    │  (ACM Agent /    │  │
│  │              │                    │   SPIRE Agent)   │  │
│  └──────────────┘                    └──────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Envoy Gateway does not handle the certificate material. It generates xDS configuration
that tells Envoy to contact the SDS server for the certificate.

## Prerequisites

### Enable SDS Secret Reference

Add `enableSDSSecretRef: true` to the EnvoyGateway configuration:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyGateway
metadata:
  name: eg
  namespace: envoy-gateway-system
spec:
  extensionAPIs:
    enableSDSSecretRef: true
```

### Deploy an SDS Server

Ensure your SDS server (e.g., ACM agent, SPIRE agent) is running alongside Envoy
and listening on a Unix Domain Socket. The socket path must be accessible to the
Envoy proxy container.

## Configuration

### Step 1: Create an SDS Reference Secret

Create a Kubernetes Secret of type `gateway.envoyproxy.io/sds`. This secret contains
no certificate material — only the SDS server address and the secret name to request:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-sds-cert
  namespace: envoy-gateway
type: gateway.envoyproxy.io/sds
stringData:
  # The identifier the SDS server uses to look up the certificate.
  # This could be an ACM ARN, a SPIFFE ID, or any name your SDS server recognizes.
  secretName: arn:aws:acm:us-east-1:123456789:certificate/abc-def-123

  # The Unix Domain Socket path where the SDS server is listening.
  url: /var/run/acm-agent/sds.sock
```

### Step 2: Reference it in a Gateway Listener

Use the SDS reference secret in the listener's `certificateRefs`, just like a regular TLS secret:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: envoy-gateway
spec:
  gatewayClassName: envoy-gateway-class
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: my-sds-cert
            kind: Secret
      allowedRoutes:
        namespaces:
          from: All
```

### Step 3: Create an HTTPRoute

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: envoy-gateway
spec:
  parentRefs:
    - name: my-gateway
      sectionName: https
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: my-service
          port: 8080
```

## Generated xDS

Envoy Gateway produces the following xDS configuration:

**Listener TLS context** — Envoy fetches the certificate from the SDS server by name:

```yaml
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      alpn_protocols:
        - h2
        - http/1.1
      tls_certificate_sds_secret_configs:
        - name: "arn:aws:acm:us-east-1:123456789:certificate/abc-def-123"
          sds_config:
            api_config_source:
              api_type: GRPC
              grpc_services:
                - envoy_grpc:
                    cluster_name: sds_var_run_acm-agent_sds.sock
```

**Static cluster** — points Envoy to the SDS server's Unix socket:

```yaml
clusters:
  - name: sds_var_run_acm-agent_sds.sock
    type: STATIC
    connect_timeout: 10s
    http2_protocol_options: {}
    load_assignment:
      cluster_name: sds_var_run_acm-agent_sds.sock
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  pipe:
                    path: /var/run/acm-agent/sds.sock
```

## Multiple Certificates

To serve multiple certificates (e.g., RSA + ECDSA), create multiple SDS reference
secrets and list them in `certificateRefs`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sds-cert-rsa
  namespace: envoy-gateway
type: gateway.envoyproxy.io/sds
stringData:
  secretName: my-rsa-cert
  url: /var/run/sds-agent/sds.sock
---
apiVersion: v1
kind: Secret
metadata:
  name: sds-cert-ecdsa
  namespace: envoy-gateway
type: gateway.envoyproxy.io/sds
stringData:
  secretName: my-ecdsa-cert
  url: /var/run/sds-agent/sds.sock
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: envoy-gateway
spec:
  gatewayClassName: envoy-gateway-class
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: sds-cert-rsa
            kind: Secret
          - name: sds-cert-ecdsa
            kind: Secret
```

## Mixing SDS and Regular Secrets

You can reference both SDS secrets and regular `kubernetes.io/tls` secrets on the same listener:

```yaml
tls:
  mode: Terminate
  certificateRefs:
    - name: sds-cert           # type: gateway.envoyproxy.io/sds
      kind: Secret
    - name: regular-tls-cert   # type: kubernetes.io/tls
      kind: Secret
```

Envoy will use SDS for the first and inline cert data for the second.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| Listener condition `InvalidCertificateRef` with "SDS Secret reference is not enabled" | `enableSDSSecretRef` is not set to `true` in EnvoyGateway config |
| Listener condition `InvalidCertificateRef` with "no secretName found" | The SDS secret is missing the `secretName` field in its data |
| Listener condition `InvalidCertificateRef` with "no url found" | The SDS secret is missing the `url` field in its data |
| TLS handshake fails at runtime | The SDS server is not reachable at the specified socket path, or it doesn't recognize the secret name |


## How It Works: Control Plane vs Data Plane

### Control Plane (Envoy Gateway)

Envoy Gateway is purely a configuration generator in this flow:

1. Reads the Kubernetes Secret of type `gateway.envoyproxy.io/sds`
2. Extracts `secretName` and `url` from the secret data
3. Generates xDS configuration:
   - Listener with `tls_certificate_sds_secret_configs` pointing to the external SDS cluster
   - Static cluster definition pointing to the Unix Domain Socket path
4. Pushes that xDS configuration to Envoy

Envoy Gateway **never** sees any certificate material. It does not fetch certs, talk to ACM, or handle rotation.

### Data Plane (Envoy + SDS Server)

The data plane handles all certificate operations:

1. Envoy receives the xDS config from Envoy Gateway
2. Envoy opens a gRPC connection to the SDS server (e.g., `/var/run/acm-agent/sds.sock`)
3. Envoy sends an SDS request with the secret name (e.g., `arn:aws:acm:...:certificate/abc-123`)
4. The SDS server (ACM Agent) receives the request, fetches the cert from the external source (e.g., AWS ACM API)
5. The SDS server returns the cert + key to Envoy over gRPC
6. Envoy uses it to terminate TLS on the listener
7. When the certificate rotates, the SDS server pushes an update — Envoy picks it up automatically with zero downtime

### Responsibility Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Control Plane                                               │
│                                                             │
│  Envoy Gateway                                              │
│    - reads K8s Secret (type: gateway.envoyproxy.io/sds)     │
│    - generates xDS (listener config + static cluster)       │
│    - pushes xDS to Envoy                                    │
│                                                             │
│  Does NOT: fetch certs, talk to ACM, handle rotation        │
└─────────────────────────────────────────────────────────────┘
         │ xDS push
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Data Plane Pod                                              │
│                                                             │
│  Envoy Proxy                        SDS Server              │
│    - terminates TLS                   - listens on UDS      │
│    - requests cert via SDS  ──────►   - resolves identifier │
│    - receives cert + key    ◄──────   - fetches from source │
│    - auto-rotates when                  (ACM, Vault, etc.)  │
│      server pushes new cert           - streams updates     │
│                                                             │
│  Does NOT: know about K8s,          Does NOT: know about    │
│  Envoy Gateway, or xDS              xDS or Gateway API      │
└─────────────────────────────────────────────────────────────┘
```
