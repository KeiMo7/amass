// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package bounty reads public bug-bounty program scopes. HackerOne, Bugcrowd,
// Intigriti and YesWeHack publish each public program's in-scope assets, and
// a community mirror republishes them as keyless feeds (bounty_platforms.json).
// When an in-scope registered domain is found, the programs whose scope lists
// a name under it are stored as Accounts (bug_bounty_program) linked to their
// page and to every asset their scope lists.
//
// This is observation only: a program listing an asset claims nothing about
// who owns it here. The ownership-gap lens and horizontal correlation weigh a
// program's scope only once the program is tied to an organization by
// first-party evidence, and only as proposals a person reviews.
package bounty

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/net/publicsuffix"
)

const (
	// feedTTL is how long a downloaded feed is used before it is fetched
	// again.
	feedTTL = 24 * time.Hour
	// feedTimeout bounds one feed download.
	feedTimeout = 5 * time.Minute
	// maxPrograms bounds the programs stored for one registered domain.
	maxPrograms = 10
	// maxScope bounds the assets stored for one program.
	maxScope = 200
)

// Property names stored on a program Account.
const (
	PropProgramName    = "bounty_program_name"
	PropProgramWebsite = "bounty_program_website"
	PropPlatform       = "bounty_platform"
)

type bountyScopes struct {
	name   string
	log    *slog.Logger
	source *et.Source

	mu      sync.Mutex
	data    *dataset
	fetched time.Time
	// dir holds the downloaded feeds; load reads them from here.
	dir string
}

func NewBountyScopes() et.Plugin {
	return &bountyScopes{
		name:   "Bug-Bounty-Scopes",
		source: &et.Source{Name: "Bug-Bounty-Scopes", Confidence: 90},
		dir:    filepath.Join(os.TempDir(), "amass-bounty"),
	}
}

func (b *bountyScopes) Name() string { return b.name }

func (b *bountyScopes) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Account), string(oam.FQDN), string(oam.Netblock), string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     b.check,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bountyScopes) Stop() { b.log.Info("Plugin stopped") }

func (b *bountyScopes) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	apex := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(apex); err != nil || dom != apex {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Account), b.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, b.source)

	d := b.load(e)
	if d == nil {
		return nil
	}
	programs := d.lookup(apex)
	if len(programs) > maxPrograms {
		e.Session.Log().Info(fmt.Sprintf("%d bug-bounty programs list %s; storing the first %d",
			len(programs), apex, maxPrograms), slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
		programs = programs[:maxPrograms]
	}
	for _, p := range programs {
		b.store(e, apex, p)
	}
	return nil
}

// load returns the program index, downloading the feeds when they are
// missing or older than a day. A feed that cannot be downloaded is read from
// the last good copy, if any.
func (b *bountyScopes) load(e *et.Event) *dataset {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.data != nil && time.Since(b.fetched) < feedTTL {
		return b.data
	}
	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		return b.data
	}

	d := newDataset()
	for _, plat := range semantics.BountyPlatforms() {
		path := filepath.Join(b.dir, plat.Key+".json")
		if fi, err := os.Stat(path); err != nil || time.Since(fi.ModTime()) >= feedTTL {
			if err := b.download(e, plat.Feed, path); err != nil {
				e.Session.Log().Warn(fmt.Sprintf("%s bug-bounty feed download failed: %v", plat.Title, err),
					slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
			}
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if err := parseFeed(plat, f, d); err != nil {
			e.Session.Log().Warn(err.Error(), slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
		}
		_ = f.Close()
	}

	b.data, b.fetched = d, time.Now()
	e.Session.Log().Info(fmt.Sprintf("bug-bounty programs loaded: %d", len(d.programs)),
		slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
	return b.data
}

// download streams a feed to dst through the session's paced client, writing
// to a temporary file first so a partial download never replaces a good one.
func (b *bountyScopes) download(e *et.Event, u, dst string) error {
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), feedTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := e.Session.Clients().Bulk
	if client == nil {
		client = e.Session.Clients().General
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}

	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// store records one program: the Account with its name, website and
// platform, its page, and the assets its scope lists. In-scope names are
// dispatched; the rest are stored and linked only.
func (b *bountyScopes) store(e *et.Event, apex string, p *program) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	db := e.Session.DB()
	acct, err := db.CreateAsset(ctx, &account.Account{
		ID: p.id(), Type: account.BugBountyProgram, Username: p.handle,
	})
	if err != nil || acct == nil {
		return nil
	}
	b.sourced(ctx, e, acct)
	for name, value := range map[string]string{
		PropProgramName: p.name, PropProgramWebsite: p.website, PropPlatform: p.platform.Title,
	} {
		if value != "" {
			_, _ = db.CreateEntityProperty(ctx, acct, &general.SimpleProperty{PropertyName: name, PropertyValue: value})
		}
	}

	if u := support.RawURLToOAM(p.page); u != nil {
		if ent, err := db.CreateAsset(ctx, u); err == nil && ent != nil {
			b.link(ctx, e, acct, "program_page", ent)
		}
	}

	stored := 0
	for _, h := range p.hosts {
		if stored >= maxScope {
			break
		}
		fqdn := &oamdns.FQDN{Name: h}
		ent, err := db.CreateAsset(ctx, fqdn)
		if err != nil || ent == nil {
			continue
		}
		stored++
		b.sourced(ctx, e, ent)
		b.link(ctx, e, acct, "in_scope", ent)
		if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 && h != apex {
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: h, Entity: ent, Session: e.Session})
		}
	}
	for _, pf := range p.prefixes {
		if stored >= maxScope {
			break
		}
		ent, err := db.CreateAsset(ctx, &oamnet.Netblock{CIDR: pf, Type: netblockType(pf)})
		if err != nil || ent == nil {
			continue
		}
		stored++
		b.sourced(ctx, e, ent)
		b.link(ctx, e, acct, "in_scope", ent)
	}
	if total := len(p.hosts) + len(p.prefixes); total > stored {
		e.Session.Log().Info(fmt.Sprintf("bug-bounty program %s lists %d assets; stored %d", p.id(), total, stored),
			slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
	}

	e.Session.Log().Info("bug-bounty program found", "program", p.id(), "domain", apex, "assets", stored,
		slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
	return acct
}

func netblockType(pf netip.Prefix) string {
	if pf.Addr().Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func (b *bountyScopes) sourced(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
}

func (b *bountyScopes) link(ctx context.Context, e *et.Event, from *dbt.Entity, label string, to *dbt.Entity) {
	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
}
