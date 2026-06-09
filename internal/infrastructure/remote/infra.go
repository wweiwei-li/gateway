// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package remote

import (
	"context"
	"sync"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/message"
	"google.golang.org/grpc/connectivity"
)

// Infra manages the creation and deletion of remotely managed proxy and rate
// limit infrastructure by delegating to a remote provider over gRPC.
//
// The underlying InfraClient is constructed lazily on the first method call
// that requires it. This avoids dialing the remote service or reading
// Kubernetes secrets during process startup, where failures would crash the
// pod before validation that the remote provider is actually being used.
type Infra struct {
	// EnvoyGateway is the configuration used to startup Envoy Gateway.
	EnvoyGateway *egv1a1.EnvoyGateway

	logger logging.Logger

	// errors is the notifier used to send async errors to the main control loop.
	errors message.RunnerErrorNotifier

	// factory builds the InfraClient on demand. It must not be nil.
	factory InfraClientFactory

	mu sync.Mutex
	ic InfraClient
}

// NewInfra returns a new Infra that will lazily build its InfraClient via the
// provided factory. The factory is invoked at most once for a successful
// construction; if it returns an error, the next call will retry.
func NewInfra(cfg *config.Server, factory InfraClientFactory, errors message.RunnerErrorNotifier) *Infra {
	return new(Infra{
		EnvoyGateway: cfg.EnvoyGateway,
		logger:       cfg.Logger.WithName(string(egv1a1.LogComponentInfrastructureRunner)),
		errors:       errors,
		factory:      factory,
	})
}

// Close releases any resources held by the underlying InfraClient. It is a
// no-op if the client was never constructed.
func (i *Infra) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ic == nil {
		return nil
	}
	err := i.ic.Close()
	i.ic = nil
	return err
}

// CreateOrUpdateProxyInfra delegates to the underlying InfraClient.
func (i *Infra) CreateOrUpdateProxyInfra(ctx context.Context, infra *ir.Infra) error {
	ic, err := i.client(ctx)
	if err != nil {
		return err
	}
	return ic.CreateOrUpdateProxyInfra(ctx, infra)
}

// DeleteProxyInfra delegates to the underlying InfraClient.
func (i *Infra) DeleteProxyInfra(ctx context.Context, infra *ir.Infra) error {
	ic, err := i.client(ctx)
	if err != nil {
		return err
	}
	return ic.DeleteProxyInfra(ctx, infra)
}

// CreateOrUpdateRateLimitInfra delegates to the underlying InfraClient.
func (i *Infra) CreateOrUpdateRateLimitInfra(ctx context.Context) error {
	ic, err := i.client(ctx)
	if err != nil {
		return err
	}
	return ic.CreateOrUpdateRateLimitInfra(ctx)
}

// DeleteRateLimitInfra delegates to the underlying InfraClient.
func (i *Infra) DeleteRateLimitInfra(ctx context.Context) error {
	ic, err := i.client(ctx)
	if err != nil {
		return err
	}
	return ic.DeleteRateLimitInfra(ctx)
}

// client returns the cached InfraClient, building it via the factory on the
// first successful call. Failed factory invocations are not cached so that
// transient errors during startup of the remote service are retried on the
// next request.
func (i *Infra) client(ctx context.Context) (InfraClient, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ic != nil {
		return i.ic, nil
	}
	ic, err := i.factory(ctx)
	if err != nil {
		return nil, err
	}
	i.ic = ic
	return ic, nil
}

// reconnectDetector tracks gRPC connectivity state transitions and reports
// when a reconnect (a return to Ready after the transport actually failed) has
// occurred. It deliberately does not fire on the initial connect, since the
// initial full IR sync is handled by the runner's first Subscribe.
//
// Crucially, it only treats TransientFailure as "the connection dropped". A
// gRPC channel also leaves Ready for IDLE after a period with no active RPCs
// (the remote infra protocol sends only sporadic unary calls, so this happens
// on a timer), and transiently passes through CONNECTING while (re)dialing.
// Neither IDLE nor CONNECTING means the consumer lost its cache, so treating
// them as a drop would fire a spurious full replay every idle cycle. Only a
// genuine transport failure (a restarted/disconnected sidecar surfaces as
// TransientFailure) arms the replay.
//
// It is a pure state machine so the edge-detection logic can be unit tested
// without driving a real gRPC connection through flaky timing.
type reconnectDetector struct {
	seenReady bool
	failed    bool
}

// observe records a new connectivity state and returns true if it represents a
// reconnect edge that should trigger an IR replay.
func (d *reconnectDetector) observe(state connectivity.State) (replay bool) {
	switch state {
	case connectivity.Ready:
		switch {
		case !d.seenReady:
			d.seenReady = true
		case d.failed:
			// We previously saw a real transport failure and are now Ready
			// again: this is a genuine reconnect.
			d.failed = false
			return true
		}
	case connectivity.TransientFailure:
		// The transport actually failed (e.g. the sidecar restarted or the
		// connection was dropped). Only after this does a return to Ready count
		// as a reconnect that warrants a replay.
		if d.seenReady {
			d.failed = true
		}
	case connectivity.Idle, connectivity.Connecting:
		// Not a failure: IDLE is gRPC parking an unused-but-healthy channel,
		// and CONNECTING is a transitional state. Do not arm a replay; the
		// connection is expected to return to Ready on its own (we nudge IDLE
		// in WatchReconnect).
	case connectivity.Shutdown:
		// Terminal; nothing to replay.
	}
	return false
}

// WatchReconnect blocks and invokes onReconnect every time the gRPC connection
// to the remote infrastructure provider transitions back to Ready after a
// genuine transport failure (TransientFailure -> ... -> Ready).
//
// This is the recovery hook for the remote provider: the IR push protocol is
// delta-based, so when the remote provider (e.g. a co-located sidecar) restarts
// and loses its cache, EG would otherwise never re-send the unchanged IR it
// already pushed. By replaying IR on reconnect, the remote provider is
// rehydrated to the current state of the world without requiring an EG restart
// or a leadership change.
//
// It does NOT replay on IDLE cycling: a gRPC channel drops to IDLE after a
// period with no active RPCs, and the remote infra protocol is sporadic unary
// traffic, so this happens routinely. Those cycles are not reconnects and must
// not trigger a replay (see reconnectDetector).
//
// It returns (without error) when the InfraClient cannot be built or is not
// backed by an observable connection, so that non-remote or test setups are
// unaffected. It returns when ctx is cancelled or the connection is shut down.
func (i *Infra) WatchReconnect(ctx context.Context, onReconnect func(context.Context)) {
	ic, err := i.client(ctx)
	if err != nil {
		i.logger.Error(err, "unable to build infra client; reconnect-driven IR replay is disabled")
		return
	}

	conn := ic.Conn()
	if conn == nil {
		// No observable connection (e.g. unit tests). Nothing to watch.
		return
	}

	var detector reconnectDetector
	for {
		state := conn.GetState()
		if state == connectivity.Shutdown {
			return
		}
		if detector.observe(state) {
			i.logger.Info("remote infra connection re-established, replaying IR")
			onReconnect(ctx)
		}
		// Nudge an Idle connection to start reconnecting so that
		// WaitForStateChange makes progress without active RPC traffic.
		if state == connectivity.Idle {
			conn.Connect()
		}
		// Block until the state changes or the context is cancelled.
		if !conn.WaitForStateChange(ctx, state) {
			return
		}
	}
}
