// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package adstxt reads the advertising seller accounts each in-scope
// registered domain lists as DIRECT in its ads.txt and app-ads.txt, and the
// ad systems' sellers.json details for them (semantics ads_txt.json). Each
// account is a shared Identifier (fingerprint ads_seller) joined to the
// stored ads.txt URL, so domains listing the same account are one hop apart.
package adstxt

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

// Properties stored on an ads_seller Identifier from the ad system's
// sellers.json.
const (
	PropSellerName   = "seller_name"
	PropSellerDomain = "seller_domain"
	PropSellerType   = "seller_type"
)

// sellersTimeout bounds one sellers.json download.
const sellersTimeout = 5 * time.Minute

type adsTxt struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	rlimit  *rate.Limiter
	catalog semantics.AdsTxt
	dir     string

	mu      sync.Mutex
	sellers map[string]sellerIndex // by ad system domain
}

// sellerIndex is one ad system's sellers.json, read on a given day.
type sellerIndex struct {
	at      time.Time
	sellers map[string]seller
}

func NewAdsTxt() et.Plugin {
	return &adsTxt{
		name:    "Ads-Txt",
		source:  &et.Source{Name: "Ads-Txt", Confidence: 90},
		rlimit:  rate.NewLimiter(rate.Every(time.Second), 1),
		dir:     filepath.Join(os.TempDir(), "amass-sellers"),
		sellers: map[string]sellerIndex{},
	}
}

func (a *adsTxt) Name() string { return a.name }

func (a *adsTxt) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)
	a.catalog = semantics.AdsTxtCatalog()

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.URL), string(oam.Identifier)},
		EventType:    oam.FQDN,
		Callback:     a.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *adsTxt) Stop() { a.log.Info("Plugin stopped") }

func (a *adsTxt) check(e *et.Event) error {
	apex, err := support.InScopeApexToCheck(e, oam.Identifier, a.source, a.name)
	if err != nil || apex == "" {
		return err
	}

	for _, path := range a.catalog.Files {
		u := "https://" + apex + path
		data, err := support.FetchBody(e, u, a.rlimit, a.catalog.MaxFileBytes)
		if err != nil {
			continue
		}
		accounts := parseAdsTxt(string(data), a.catalog.MaxAccounts)
		if len(accounts) > 0 {
			a.store(e, apex, u, accounts)
		}
	}
	return nil
}

// store records the ads.txt URL, joined to its domain, and each DIRECT
// account as a fingerprint Identifier with its sellers.json details.
func (a *adsTxt) store(e *et.Event, apex, raw string, accounts []account) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()
	sess := e.Session
	db := sess.DB()

	path := strings.TrimPrefix(raw, "https://"+apex)
	urlEnt, err := db.CreateAsset(ctx, &oamurl.URL{Raw: raw, Scheme: "https", Host: apex, Path: path, Port: 443})
	if err != nil || urlEnt == nil {
		return
	}
	support.AddSource(ctx, sess, urlEnt, a.source)
	if dom, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: apex}); err == nil && dom != nil {
		support.Link(ctx, sess, urlEnt, "domain", dom, a.source)
	}

	for _, acct := range accounts {
		value := acct.key()
		if !support.StoreFingerprint(e, urlEnt, a.source, fingerprint.AdsSeller, value) {
			continue
		}
		s, ok := a.seller(e, acct)
		if !ok {
			continue
		}
		ident, err := db.CreateAsset(ctx, &general.Identifier{UniqueID: fingerprint.AdsSeller + ":" + value,
			ID: value, Type: fingerprint.AdsSeller})
		if err != nil || ident == nil {
			continue
		}
		support.AddProperty(ctx, sess, ident, PropSellerName, s.Name)
		support.AddProperty(ctx, sess, ident, PropSellerDomain, strings.ToLower(s.Domain))
		support.AddProperty(ctx, sess, ident, PropSellerType, strings.ToUpper(s.Type))
	}
}

// seller returns the ad system's sellers.json entry for an account, reading
// the ad system's file at most once a day.
func (a *adsTxt) seller(e *et.Event, acct account) (seller, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx, ok := a.sellers[acct.system]
	ttl := time.Duration(a.catalog.SellersTTLHours) * time.Hour
	if !ok || time.Since(idx.at) >= ttl {
		idx = sellerIndex{at: time.Now(), sellers: a.loadSellers(e, acct.system, ttl)}
		a.sellers[acct.system] = idx
	}
	s, ok := idx.sellers[acct.id]
	return s, ok
}

// loadSellers downloads (or reuses the day's copy of) an ad system's
// sellers.json and indexes it by seller ID. A file that is missing, too
// large or unreadable gives none.
func (a *adsTxt) loadSellers(e *et.Event, system string, ttl time.Duration) map[string]seller {
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return nil
	}
	path := filepath.Join(a.dir, system+".json")
	if err := support.CachedDownload(e, "https://"+system+a.catalog.SellersPath, path, ttl, sellersTimeout,
		a.catalog.MaxSellersBytes); err != nil {
		e.Session.Log().Debug("sellers.json not read", "system", system, "error", err.Error(),
			slog.Group("plugin", "name", a.name, "handler", a.name+"-Handler"))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	m, err := parseSellers(f)
	if err != nil {
		return nil
	}
	return m
}
