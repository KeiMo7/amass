// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package routing reads the routing security records of the netblocks in
// scope: the routing registry (IRR) route objects that name each netblock's
// maintainer, and the RPKI Route Origin Authorizations (ROAs) that say which
// autonomous systems may announce it. Both come from RIPEstat with no key.
// For each operator maintainer it also asks a routing registry for every
// other route object that maintainer keeps, which finds the operator's other
// netblocks.
//
// Everything is an observation: a Netblock --irr_maintainer--> Identifier, a
// Netblock --rpki_origin--> AutonomousSystem, and the netblock's rpki_status.
// The infrastructure lens decides what they say about ownership.
package routing

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// Property names this plugin stores.
const (
	// PropRPKIStatus is a netblock's RPKI validity for its announced origin:
	// valid, invalid or unknown (no ROA covers it).
	PropRPKIStatus = "rpki_status"
	// PropIRRRoutes is how many route objects a maintainer keeps, and
	// PropIRROrigin each origin AS among them (at most max_origins + 1).
	PropIRRRoutes = "irr_routes"
	PropIRROrigin = "irr_origin"
)

const (
	// maxOrigins bounds the announced origins checked per netblock.
	maxOrigins = 3
	// maintainerTTL is how long one maintainer's route objects are not asked
	// for again.
	maintainerTTL = 24 * time.Hour
	// whoisReadLimit bounds a routing registry answer.
	whoisReadLimit = 4 << 20
)

type routingRecords struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	rlimit  *rate.Limiter
	catalog semantics.RoutingRegistries

	mu    sync.Mutex
	asked map[string]time.Time
}

func NewRoutingRecords() et.Plugin {
	return &routingRecords{
		name:   "RPKI-IRR",
		source: &et.Source{Name: "RPKI-IRR", Confidence: 90},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		asked:  map[string]time.Time{},
	}
}

func (r *routingRecords) Name() string { return r.name }

func (r *routingRecords) Start(reg et.Registry) error {
	r.log = reg.Log().WithGroup("plugin").With("name", r.name)
	r.catalog = semantics.RoutingRegistryCatalog()

	if err := reg.RegisterHandler(&et.Handler{
		Plugin:       r,
		Name:         r.name + "-Handler",
		Position:     30,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier), string(oam.AutonomousSystem), string(oam.Netblock)},
		EventType:    oam.Netblock,
		Callback:     r.check,
	}); err != nil {
		return err
	}

	r.log.Info("Plugin started")
	return nil
}

func (r *routingRecords) Stop() { r.log.Info("Plugin stopped") }

func (r *routingRecords) check(e *et.Event) error {
	nb, ok := e.Entity.Asset.(*oamnet.Netblock)
	if !ok || !nb.CIDR.IsValid() {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(nb, 0); conf == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Netblock), string(oam.Identifier), r.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, r.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, r.source)

	prefix := nb.CIDR.Masked()
	if objs, err := r.statWhois(e, prefix); err == nil {
		for _, m := range r.maintainers(objs, prefix) {
			id := r.storeMaintainer(e, e.Entity, m)
			if id != nil {
				r.expand(e, id, m)
			}
		}
	}
	r.rpki(e, e.Entity, prefix)
	return nil
}

// maintainer is an operator's handle in one routing registry.
type maintainer struct {
	source, handle string
}

func (m maintainer) id() string { return m.source + ":" + m.handle }

// maintainers returns the operator maintainers of the route objects for the
// prefix itself or more specific prefixes within it; a covering route object
// is a provider's aggregate, and a registry's own maintainers name no
// operator.
func (r *routingRecords) maintainers(objs []routeObject, prefix netip.Prefix) []maintainer {
	seen := map[maintainer]bool{}
	var out []maintainer
	for _, o := range objs {
		if o.prefix.Bits() < prefix.Bits() || !prefix.Contains(o.prefix.Addr()) {
			continue
		}
		for _, h := range o.maintainers {
			m := maintainer{source: o.source, handle: h}
			if r.catalog.RegistryMaintainer(h) || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// statGet fetches one RIPEstat data call.
func (r *routingRecords) statGet(e *et.Event, call string, params url.Values) ([]byte, error) {
	params.Set("sourceapp", r.catalog.SourceApp)
	u := fmt.Sprintf("%s/%s/data.json?%s", strings.TrimSuffix(r.catalog.StatAPI, "/"), call, params.Encode())

	_ = support.WaitLimit(e.Session.Ctx(), r.rlimit)
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat %s: unexpected answer", call)
	}
	return []byte(resp.Body), nil
}

func (r *routingRecords) statWhois(e *et.Event, prefix netip.Prefix) ([]routeObject, error) {
	data, err := r.statGet(e, "whois", url.Values{"resource": {prefix.String()}})
	if err != nil {
		return nil, err
	}
	return parseStatWhois(data)
}

// storeMaintainer records the maintainer as an Identifier linked from the
// netblock.
func (r *routingRecords) storeMaintainer(e *et.Event, nbent *dbt.Entity, m maintainer) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	id, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
		UniqueID: general.IRRMaintainer + ":" + m.id(), ID: m.id(), Type: general.IRRMaintainer,
	})
	if err != nil || id == nil {
		return nil
	}
	r.sourced(ctx, e, id)
	r.link(ctx, e, nbent, "irr_maintainer", id)
	return id
}

// expand asks the routing registry for every route object the maintainer
// keeps, once a day. It records how many there are and their origin ASes on
// the maintainer, and links each route's netblock to it unless the maintainer
// keeps more than max_routes: an ISP, host or registry keeping objects for
// many customers.
func (r *routingRecords) expand(e *et.Event, id *dbt.Entity, m maintainer) {
	r.mu.Lock()
	if t, ok := r.asked[m.id()]; ok && time.Since(t) < maintainerTTL {
		r.mu.Unlock()
		return
	}
	r.asked[m.id()] = time.Now()
	r.mu.Unlock()

	text, err := r.whois(e.Session.Ctx(), fmt.Sprintf("-s %s -i mnt-by %s", m.source, m.handle))
	if err != nil {
		e.Session.Log().Debug("routing registry query failed", "maintainer", m.id(), "error", err,
			slog.Group("plugin", "name", r.name, "handler", r.name+"-Handler"))
		return
	}
	var routes []routeObject
	for _, o := range parseRPSL(text) {
		if o.source == m.source {
			routes = append(routes, o)
		}
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()
	r.property(ctx, e, id, PropIRRRoutes, strconv.Itoa(len(routes)))
	origins := map[int]bool{}
	for _, o := range routes {
		origins[o.origin] = true
	}
	var nums []int
	for n := range origins {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for i, n := range nums {
		if i > r.catalog.MaxOrigins {
			break
		}
		r.property(ctx, e, id, PropIRROrigin, fmt.Sprintf("AS%d", n))
	}
	if len(routes) > r.catalog.MaxRoutes {
		return
	}

	for _, o := range routes {
		kind := "IPv4"
		if o.prefix.Addr().Is6() {
			kind = "IPv6"
		}
		nbent, err := e.Session.DB().CreateAsset(ctx, &oamnet.Netblock{CIDR: o.prefix, Type: kind})
		if err != nil || nbent == nil {
			continue
		}
		r.sourced(ctx, e, nbent)
		r.link(ctx, e, nbent, "irr_maintainer", id)
	}
	e.Session.Log().Info("routing registry maintainer read", "maintainer", m.id(), "routes", len(routes),
		slog.Group("plugin", "name", r.name, "handler", r.name+"-Handler"))
}

// whois sends one query to the routing registry whois server.
func (r *routingRecords) whois(ctx context.Context, query string) (string, error) {
	_ = support.WaitLimit(ctx, r.rlimit)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	host, port, err := net.SplitHostPort(r.catalog.IRRWhois)
	if err != nil {
		return "", err
	}
	conn, err := amassnet.NewDialContext(10*time.Second)(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(conn, whoisReadLimit))
	if err != nil && len(data) == 0 {
		return "", err
	}
	return string(data), nil
}

// rpki checks the netblock against RPKI for each AS that announces it, and
// records its validity and every AS a valid ROA authorizes to announce it.
func (r *routingRecords) rpki(e *et.Event, nbent *dbt.Entity, prefix netip.Prefix) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	edges, err := e.Session.DB().IncomingEdges(ctx, nbent, time.Time{}, "announces")
	if err != nil || len(edges) == 0 {
		return
	}

	status := ""
	authorized := map[int]bool{}
	for i, edge := range edges {
		if i >= maxOrigins {
			break
		}
		asent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || asent == nil {
			continue
		}
		as, ok := asent.Asset.(*oamnet.AutonomousSystem)
		if !ok {
			continue
		}

		data, err := r.statGet(e, "rpki-validation", url.Values{"resource": {fmt.Sprintf("AS%d", as.Number)},
			"prefix": {prefix.String()}})
		if err != nil {
			continue
		}
		s, roas, err := parseRPKIValidation(data)
		if err != nil {
			continue
		}
		// valid for any announced origin wins; otherwise the first answer
		if status == "" || s == "valid" {
			status = s
		}
		for _, ro := range roas {
			if ro.validity == "valid" && ro.covers(prefix) {
				authorized[ro.origin] = true
			}
		}
	}

	if status != "" {
		r.property(ctx, e, nbent, PropRPKIStatus, status)
	}
	for n := range authorized {
		asent, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: n})
		if err != nil || asent == nil {
			continue
		}
		r.sourced(ctx, e, asent)
		r.link(ctx, e, nbent, "rpki_origin", asent)
	}
}

func (r *routingRecords) sourced(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &general.SourceProperty{
		Source:     r.source.Name,
		Confidence: r.source.Confidence,
	})
}

func (r *routingRecords) property(ctx context.Context, e *et.Event, ent *dbt.Entity, name, value string) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

func (r *routingRecords) link(ctx context.Context, e *et.Event, from *dbt.Entity, label string, to *dbt.Entity) {
	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     r.source.Name,
		Confidence: r.source.Confidence,
	})
}
