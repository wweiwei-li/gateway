// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package remote

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/message"
)

// fakeInfraClient is a stub implementation of InfraClient used to verify that
// the Infra wrapper correctly delegates to the underlying client.
type fakeInfraClient struct {
	closeCalled               bool
	createOrUpdateProxyCalled bool
	deleteProxyCalled         bool
	createOrUpdateRLCalled    bool
	deleteRLCalled            bool

	gotProxyInfra  *ir.Infra
	gotDeleteInfra *ir.Infra

	closeErr               error
	createOrUpdateProxyErr error
	deleteProxyErr         error
	createOrUpdateRLErr    error
	deleteRLErr            error
}

func (f *fakeInfraClient) Close() error {
	f.closeCalled = true
	return f.closeErr
}

func (f *fakeInfraClient) CreateOrUpdateProxyInfra(_ context.Context, infra *ir.Infra) error {
	f.createOrUpdateProxyCalled = true
	f.gotProxyInfra = infra
	return f.createOrUpdateProxyErr
}

func (f *fakeInfraClient) DeleteProxyInfra(_ context.Context, infra *ir.Infra) error {
	f.deleteProxyCalled = true
	f.gotDeleteInfra = infra
	return f.deleteProxyErr
}

func (f *fakeInfraClient) CreateOrUpdateRateLimitInfra(_ context.Context) error {
	f.createOrUpdateRLCalled = true
	return f.createOrUpdateRLErr
}

func (f *fakeInfraClient) DeleteRateLimitInfra(_ context.Context) error {
	f.deleteRLCalled = true
	return f.deleteRLErr
}

// Conn returns nil: the fake is not backed by an observable gRPC connection,
// so reconnect-driven replay is disabled for it.
func (f *fakeInfraClient) Conn() *grpc.ClientConn {
	return nil
}

// fakeFactory returns an InfraClientFactory that hands back the supplied
// fakeInfraClient and counts how many times it was invoked. If err is
// non-nil, the factory returns the error instead and the client is never
// returned.
type fakeFactory struct {
	calls  int
	client *fakeInfraClient
	err    error
}

func (f *fakeFactory) build(_ context.Context) (InfraClient, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

// newInfraWithFake returns an Infra wired to a factory that returns fc.
func newInfraWithFake(t *testing.T, fc *fakeInfraClient) (*Infra, *fakeFactory) {
	t.Helper()
	cfg, err := config.New(io.Discard, io.Discard)
	require.NoError(t, err)
	notifier := new(message.RunnerErrorNotifier{
		RunnerName:   "infrastructure",
		RunnerErrors: new(message.RunnerErrors{}),
	})
	ff := new(fakeFactory{client: fc})
	return NewInfra(cfg, ff.build, *notifier), ff
}

func TestNewInfra(t *testing.T) {
	t.Run("does_not_invoke_factory", func(t *testing.T) {
		cfg, err := config.New(io.Discard, io.Discard)
		require.NoError(t, err)
		notifier := message.RunnerErrorNotifier{
			RunnerName:   "infrastructure",
			RunnerErrors: new(message.RunnerErrors{}),
		}

		ff := new(fakeFactory{client: new(fakeInfraClient{})})
		infra := NewInfra(cfg, ff.build, notifier)
		require.NotNil(t, infra)
		assert.Equal(t, cfg.EnvoyGateway, infra.EnvoyGateway)
		assert.NotNil(t, infra.logger)
		assert.Equal(t, 0, ff.calls,
			"factory must not be invoked at construction time")
	})
}

func TestInfra_Close(t *testing.T) {
	t.Run("noop_when_client_never_built", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, ff := newInfraWithFake(t, fc)

		require.NoError(t, infra.Close())
		assert.False(t, fc.closeCalled,
			"Close must not invoke the factory or call Close on a never-built client")
		assert.Equal(t, 0, ff.calls)
	})

	t.Run("closes_built_client", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)

		// Force the factory to run.
		require.NoError(t, infra.CreateOrUpdateRateLimitInfra(context.Background()))

		require.NoError(t, infra.Close())
		assert.True(t, fc.closeCalled)
	})

	t.Run("close_is_idempotent", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)
		require.NoError(t, infra.CreateOrUpdateRateLimitInfra(context.Background()))

		require.NoError(t, infra.Close())
		fc.closeCalled = false
		require.NoError(t, infra.Close())
		assert.False(t, fc.closeCalled,
			"second Close must not call the underlying client again")
	})

	t.Run("propagates_error", func(t *testing.T) {
		wantErr := errors.New("close failed")
		fc := new(fakeInfraClient{closeErr: wantErr})
		infra, _ := newInfraWithFake(t, fc)
		require.NoError(t, infra.CreateOrUpdateRateLimitInfra(context.Background()))

		err := infra.Close()
		require.ErrorIs(t, err, wantErr)
		assert.True(t, fc.closeCalled)
	})
}

func TestInfra_LazyClientConstruction(t *testing.T) {
	t.Run("factory_invoked_once_on_repeated_calls", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, ff := newInfraWithFake(t, fc)

		require.NoError(t, infra.CreateOrUpdateRateLimitInfra(context.Background()))
		require.NoError(t, infra.DeleteRateLimitInfra(context.Background()))
		require.NoError(t, infra.CreateOrUpdateProxyInfra(context.Background(), new(ir.Infra)))

		assert.Equal(t, 1, ff.calls,
			"factory should be invoked exactly once after a successful build")
	})

	t.Run("factory_error_propagates_and_retries", func(t *testing.T) {
		buildErr := errors.New("dial failed")
		ff := new(fakeFactory{err: buildErr})
		cfg, err := config.New(io.Discard, io.Discard)
		require.NoError(t, err)
		notifier := message.RunnerErrorNotifier{
			RunnerName:   "infrastructure",
			RunnerErrors: new(message.RunnerErrors{}),
		}
		infra := NewInfra(cfg, ff.build, notifier)

		err = infra.CreateOrUpdateRateLimitInfra(context.Background())
		require.ErrorIs(t, err, buildErr)
		err = infra.CreateOrUpdateRateLimitInfra(context.Background())
		require.ErrorIs(t, err, buildErr)
		assert.Equal(t, 2, ff.calls,
			"failed factory builds must not be cached, so each call retries")
	})
}

func TestInfra_CreateOrUpdateProxyInfra(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)
		input := new(ir.Infra{Proxy: new(ir.ProxyInfra{Name: "proxy", Namespace: "ns"})})

		require.NoError(t, infra.CreateOrUpdateProxyInfra(context.Background(), input))
		assert.True(t, fc.createOrUpdateProxyCalled)
		assert.Same(t, input, fc.gotProxyInfra)
	})

	t.Run("propagates_error", func(t *testing.T) {
		wantErr := errors.New("create failed")
		fc := new(fakeInfraClient{createOrUpdateProxyErr: wantErr})
		infra, _ := newInfraWithFake(t, fc)

		err := infra.CreateOrUpdateProxyInfra(context.Background(), new(ir.Infra))
		require.ErrorIs(t, err, wantErr)
		assert.True(t, fc.createOrUpdateProxyCalled)
	})
}

func TestInfra_DeleteProxyInfra(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)
		input := new(ir.Infra{Proxy: new(ir.ProxyInfra{Name: "proxy", Namespace: "ns"})})

		require.NoError(t, infra.DeleteProxyInfra(context.Background(), input))
		assert.True(t, fc.deleteProxyCalled)
		assert.Same(t, input, fc.gotDeleteInfra)
	})

	t.Run("propagates_error", func(t *testing.T) {
		wantErr := errors.New("delete failed")
		fc := new(fakeInfraClient{deleteProxyErr: wantErr})
		infra, _ := newInfraWithFake(t, fc)

		err := infra.DeleteProxyInfra(context.Background(), new(ir.Infra))
		require.ErrorIs(t, err, wantErr)
		assert.True(t, fc.deleteProxyCalled)
	})
}

func TestInfra_CreateOrUpdateRateLimitInfra(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)

		require.NoError(t, infra.CreateOrUpdateRateLimitInfra(context.Background()))
		assert.True(t, fc.createOrUpdateRLCalled)
	})

	t.Run("propagates_error", func(t *testing.T) {
		wantErr := errors.New("ratelimit create failed")
		fc := new(fakeInfraClient{createOrUpdateRLErr: wantErr})
		infra, _ := newInfraWithFake(t, fc)

		err := infra.CreateOrUpdateRateLimitInfra(context.Background())
		require.ErrorIs(t, err, wantErr)
		assert.True(t, fc.createOrUpdateRLCalled)
	})
}

func TestInfra_DeleteRateLimitInfra(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fc := new(fakeInfraClient{})
		infra, _ := newInfraWithFake(t, fc)

		require.NoError(t, infra.DeleteRateLimitInfra(context.Background()))
		assert.True(t, fc.deleteRLCalled)
	})

	t.Run("propagates_error", func(t *testing.T) {
		wantErr := errors.New("ratelimit delete failed")
		fc := new(fakeInfraClient{deleteRLErr: wantErr})
		infra, _ := newInfraWithFake(t, fc)

		err := infra.DeleteRateLimitInfra(context.Background())
		require.ErrorIs(t, err, wantErr)
		assert.True(t, fc.deleteRLCalled)
	})
}

func TestReconnectDetector(t *testing.T) {
	const (
		ready = connectivity.Ready
		idle  = connectivity.Idle
		tf    = connectivity.TransientFailure
		conn  = connectivity.Connecting
		shut  = connectivity.Shutdown
	)

	// replayCount drives a detector through a sequence of states and returns
	// how many reconnect edges (replays) it reported.
	replayCount := func(states ...connectivity.State) int {
		var d reconnectDetector
		count := 0
		for _, s := range states {
			if d.observe(s) {
				count++
			}
		}
		return count
	}

	t.Run("initial_connect_does_not_replay", func(t *testing.T) {
		// First time reaching Ready is the initial sync, handled elsewhere.
		assert.Equal(t, 0, replayCount(conn, ready))
	})

	t.Run("ready_then_transient_failure_then_ready_replays_once", func(t *testing.T) {
		// A genuine transport failure (e.g. sidecar restart) followed by
		// recovery is the one case that replays.
		assert.Equal(t, 1, replayCount(ready, tf, ready))
	})

	t.Run("transient_failure_via_connecting_replays_once", func(t *testing.T) {
		// Real reconnect path: Ready -> TransientFailure -> Connecting -> Ready.
		assert.Equal(t, 1, replayCount(ready, tf, conn, ready))
	})

	t.Run("idle_cycle_does_not_replay", func(t *testing.T) {
		// IDLE is gRPC parking a healthy-but-unused channel; the watcher nudges
		// it back to Ready. This must NOT be treated as a reconnect, otherwise
		// every idle cycle (~every 30m of no IR changes) fires a spurious
		// full replay.
		assert.Equal(t, 0, replayCount(ready, idle, conn, ready))
	})

	t.Run("repeated_idle_cycles_never_replay", func(t *testing.T) {
		assert.Equal(t, 0, replayCount(ready, idle, conn, ready, idle, conn, ready))
	})

	t.Run("two_real_failures_replay_twice", func(t *testing.T) {
		assert.Equal(t, 2, replayCount(ready, tf, ready, tf, conn, ready))
	})

	t.Run("idle_between_failures_does_not_add_replays", func(t *testing.T) {
		// Only the transient-failure recoveries count; interleaved idle cycles
		// are ignored.
		assert.Equal(t, 2, replayCount(ready, idle, ready, tf, ready, idle, ready, tf, ready))
	})

	t.Run("staying_ready_does_not_replay", func(t *testing.T) {
		assert.Equal(t, 0, replayCount(ready, ready, ready))
	})

	t.Run("failure_without_recovery_does_not_replay", func(t *testing.T) {
		assert.Equal(t, 0, replayCount(ready, tf, conn))
	})

	t.Run("shutdown_does_not_replay", func(t *testing.T) {
		assert.Equal(t, 0, replayCount(ready, tf, shut))
	})

	t.Run("failure_before_ever_ready_does_not_replay", func(t *testing.T) {
		// If we never reached Ready, a return to Ready is the initial connect.
		assert.Equal(t, 0, replayCount(conn, tf, conn, ready))
	})
}

func TestInfra_WatchReconnect_NoConn(t *testing.T) {
	// When the client has no observable connection, WatchReconnect returns
	// immediately without invoking onReconnect.
	fc := &fakeInfraClient{}
	infra, _ := newInfraWithFake(t, fc)

	called := false
	infra.WatchReconnect(context.Background(), func(context.Context) {
		called = true
	})
	assert.False(t, called, "onReconnect must not be called without a connection")
}
