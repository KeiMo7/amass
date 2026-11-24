// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package testsupport provides in-memory fakes for engine control-plane tests.
package testsupport

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/yl2chen/cidranger"
)

// FakeScope is an empty, no-op Scope implementation for handler tests.
type FakeScope struct{}

func (FakeScope) Add(oam.Asset) bool { return false }
func (FakeScope) IsAssetInScope(a oam.Asset, conf int) (oam.Asset, int) {
	return nil, 0
}
func (FakeScope) AddBlacklist(string)          {}
func (FakeScope) IsBlacklisted(oam.Asset) bool { return false }
func (FakeScope) IsAssociated(*et.Association) ([]*et.Association, error) {
	return nil, nil
}
func (FakeScope) AssetsWithAssociation(*dbt.Entity) []*dbt.Entity { return nil }
func (FakeScope) Domains() []string                               { return nil }
func (FakeScope) FQDNs() []*oamdns.FQDN                           { return nil }
func (FakeScope) AddDomain(string) bool                           { return false }
func (FakeScope) Addresses() []string                             { return nil }
func (FakeScope) AddAddress(string) bool                          { return false }
func (FakeScope) IPAddresses() []*oamnet.IPAddress                { return nil }
func (FakeScope) CIDRs() []string                                 { return nil }
func (FakeScope) AddCIDR(string) bool                             { return false }
func (FakeScope) Netblocks() []*oamnet.Netblock                   { return nil }
func (FakeScope) ASNs() []int                                     { return nil }
func (FakeScope) AddASN(int) bool                                 { return false }
func (FakeScope) AutonomousSystems() []*oamnet.AutonomousSystem   { return nil }
func (FakeScope) AddOrgByName(string) bool                        { return false }
func (FakeScope) Organizations() []*oamorg.Organization           { return nil }
func (FakeScope) Locations() []*oamcon.Location                   { return nil }
func (FakeScope) AddLocation(*oamcon.Location) bool               { return false }

// FakeSession implements just enough of et.Session for the HTTP handlers.
type FakeSession struct {
	id    uuid.UUID
	ps    *pubsub.Logger
	stats *et.SessionStats
	scope et.Scope
}

func NewFakeSession(id uuid.UUID) *FakeSession {
	return &FakeSession{
		id:    id,
		ps:    pubsub.NewLogger(),
		stats: new(et.SessionStats),
		scope: FakeScope{},
	}
}

func (f *FakeSession) ID() uuid.UUID                   { return f.id }
func (f *FakeSession) Ctx() context.Context            { return context.Background() }
func (f *FakeSession) Log() *slog.Logger               { return slog.Default() }
func (f *FakeSession) PubSub() *pubsub.Logger          { return f.ps }
func (f *FakeSession) NetSem() et.SessionSemaphone     { return nil }
func (f *FakeSession) Config() *config.Config          { return config.NewConfig() }
func (f *FakeSession) Scope() et.Scope                 { return f.scope }
func (f *FakeSession) StartTime() time.Time            { return time.Now() }
func (f *FakeSession) DB() repository.Repository       { return nil }
func (f *FakeSession) Backlog() et.Backlog             { return nil }
func (f *FakeSession) Pipelines() et.SessionPipelines  { return nil }
func (f *FakeSession) Clients() *et.SessionHTTPClients { return nil }
func (f *FakeSession) CIDRanger() cidranger.Ranger     { return nil }
func (f *FakeSession) TmpDir() string                  { return "" }
func (f *FakeSession) Stats() *et.SessionStats         { return f.stats }
func (f *FakeSession) Done() bool                      { return false }
func (f *FakeSession) Kill()                           {}

// FakeManager is an in-memory SessionManager for handler tests.
type FakeManager struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]et.Session
}

func NewFakeManager() *FakeManager {
	return &FakeManager{sessions: make(map[uuid.UUID]et.Session)}
}

// Add inserts a session into the fake manager.
func (m *FakeManager) Add(s et.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID()] = s
}

func (m *FakeManager) NewSession(*config.Config) (et.Session, error) {
	s := NewFakeSession(uuid.New())
	m.Add(s)
	return s, nil
}
func (m *FakeManager) AddSession(s et.Session) error { m.Add(s); return nil }
func (m *FakeManager) CancelSession(id uuid.UUID) {
	m.mu.Lock()
	if s, ok := m.sessions[id]; ok {
		s.Kill()
		delete(m.sessions, id)
	}
	m.mu.Unlock()
}
func (m *FakeManager) GetSession(id uuid.UUID) et.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}
func (m *FakeManager) GetSessions() []et.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]et.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}
func (m *FakeManager) Shutdown() {}

// FakeDispatcher accepts events without running any plugin pipeline.
type FakeDispatcher struct{}

func (FakeDispatcher) DispatchEvent(*et.Event) error { return nil }
func (FakeDispatcher) Shutdown()                     {}
