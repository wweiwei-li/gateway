// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/message"
)

// fakeManager is a stub infrastructure.Manager used to observe what the runner
// pushes during a reconnect replay. It optionally implements reconnectWatcher.
type fakeManager struct {
	mu      sync.Mutex
	created []*ir.Infra
}

func (m *fakeManager) Close() error { return nil }

func (m *fakeManager) CreateOrUpdateProxyInfra(_ context.Context, infra *ir.Infra) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, infra)
	return nil
}

func (m *fakeManager) DeleteProxyInfra(_ context.Context, _ *ir.Infra) error { return nil }

func (m *fakeManager) CreateOrUpdateRateLimitInfra(_ context.Context) error { return nil }

func (m *fakeManager) DeleteRateLimitInfra(_ context.Context) error { return nil }

func (m *fakeManager) createdCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.created)
}

// infraWithListeners builds a minimal Infra that passes the "has listeners"
// guard in replayProxyInfra.
func infraWithListeners(name string) *ir.Infra {
	return &ir.Infra{
		Proxy: &ir.ProxyInfra{
			Name:      name,
			Namespace: "ns",
			Listeners: []*ir.ProxyListener{{Name: "l1"}},
		},
	}
}

func newTestRunner(t *testing.T, mgr *fakeManager) *Runner {
	t.Helper()
	r := New(&Config{InfraIR: new(message.InfraIR)})
	r.mgr = mgr
	r.Logger = logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo)
	return r
}

func TestReplayProxyInfra(t *testing.T) {
	t.Run("replays_all_entries_with_listeners", func(t *testing.T) {
		mgr := &fakeManager{}
		r := newTestRunner(t, mgr)

		r.InfraIR.Store("gw-a", infraWithListeners("a"))
		r.InfraIR.Store("gw-b", infraWithListeners("b"))

		r.replayProxyInfra(context.Background())

		assert.Equal(t, 2, mgr.createdCount(),
			"both gateways with listeners should be replayed")
	})

	t.Run("skips_infra_without_listeners", func(t *testing.T) {
		mgr := &fakeManager{}
		r := newTestRunner(t, mgr)

		r.InfraIR.Store("gw-a", infraWithListeners("a"))
		// No listeners -> must be skipped, matching the subscription path.
		r.InfraIR.Store("gw-empty", &ir.Infra{Proxy: &ir.ProxyInfra{Name: "empty"}})
		// Nil proxy -> must be skipped without panicking.
		r.InfraIR.Store("gw-nilproxy", &ir.Infra{})

		r.replayProxyInfra(context.Background())

		require.Equal(t, 1, mgr.createdCount())
		assert.Equal(t, "a", mgr.created[0].Proxy.Name)
	})

	t.Run("no_entries_is_a_noop", func(t *testing.T) {
		mgr := &fakeManager{}
		r := newTestRunner(t, mgr)

		r.replayProxyInfra(context.Background())

		assert.Equal(t, 0, mgr.createdCount())
	})
}
