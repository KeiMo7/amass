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
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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
		Transforms: []string{string(oam.URL), string(oam.Identifier), string(oam.ContactRecord), string(oam.FQDN),
			string(oam.Phone)},
		EventType: oam.FQDN,
		Callback:  a.check,
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
		if f := parseAdsTxt(string(data), a.catalog.MaxAccounts); len(f.accounts) > 0 || f.ownerDomain != "" {
			a.store(e, apex, u, f)
		}
	}
	return nil
}

// store records the ads.txt URL, joined to its domain, with the owner domain
// it names, and each DIRECT account as a fingerprint Identifier with its
// sellers.json details.
func (a *adsTxt) store(e *et.Event, apex, raw string, f adsFile) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()
	sess := e.Session
	db := sess.DB()

	u := support.RawURLToOAM(raw)
	if u == nil {
		return
	}
	urlEnt, err := db.CreateAsset(ctx, u)
	if err != nil || urlEnt == nil {
		return
	}
	support.AddSource(ctx, sess, urlEnt, a.source)
	if dom, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: apex}); err == nil && dom != nil {
		support.Link(ctx, sess, urlEnt, "domain", dom, a.source)
	}
	a.storeContact(ctx, e, urlEnt, raw, f)

	for _, acct := range f.accounts {
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

// storeContact records what the file names about its owner as the file's
// ContactRecord (URL --contact--> ContactRecord): the OWNERDOMAIN as an FQDN,
// and each contact value as an email Identifier, a URL or a phone.
func (a *adsTxt) storeContact(ctx context.Context, e *et.Event, urlEnt *dbt.Entity, raw string, f adsFile) {
	if f.ownerDomain == "" && len(f.contacts) == 0 {
		return
	}
	sess := e.Session
	db := sess.DB()

	cr, err := db.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: raw})
	if err != nil || cr == nil {
		return
	}
	support.AddSource(ctx, sess, cr, a.source)
	support.Link(ctx, sess, urlEnt, "contact", cr, a.source)

	if f.ownerDomain != "" {
		if dom, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: f.ownerDomain}); err == nil && dom != nil {
			support.AddSource(ctx, sess, dom, a.source)
			support.Link(ctx, sess, cr, "fqdn", dom, a.source)
		}
	}
	for _, c := range f.contacts {
		c = strings.TrimPrefix(c, "mailto:")
		switch {
		case strings.Contains(c, "@"):
			email := strings.ToLower(c)
			if ent, err := db.CreateAsset(ctx, &general.Identifier{UniqueID: general.EmailAddress + ":" + email,
				ID: email, Type: general.EmailAddress}); err == nil && ent != nil {
				support.AddSource(ctx, sess, ent, a.source)
				support.Link(ctx, sess, cr, "id", ent, a.source)
			}
		case strings.HasPrefix(strings.ToLower(c), "http://") || strings.HasPrefix(strings.ToLower(c), "https://"):
			if u := support.RawURLToOAM(c); u != nil {
				if ent, err := db.CreateAsset(ctx, u); err == nil && ent != nil {
					support.AddSource(ctx, sess, ent, a.source)
					support.Link(ctx, sess, cr, "url", ent, a.source)
				}
			}
		default:
			if ph := support.PhoneToOAMPhone(c, "", ""); ph != nil {
				if ent, err := db.CreateAsset(ctx, ph); err == nil && ent != nil {
					support.AddSource(ctx, sess, ent, a.source)
					support.Link(ctx, sess, cr, "phone", ent, a.source)
				}
			}
		}
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
