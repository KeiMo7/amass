// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package bimi reads a domain's Brand Indicators for Message Identification
// (BIMI) record and the mark certificate it names. A BIMI record
// (default._bimi.<domain> TXT, "v=BIMI1; l=<logo>; a=<evidence>") points to a
// Verified Mark Certificate or Common Mark Certificate: an X.509 certificate a
// certification authority issues only after verifying the organization as for
// Extended Validation and, for a registered mark, its trademark registration.
//
// A mark certificate that lists the domain is stored like any TLS certificate
// (the certificate handler records its domains and its subject, the
// CA-verified organization), so it feeds the certificate signals. The mark
// details it carries go on the certificate's subject ContactRecord: the
// trademark registration and the Legal Entity Identifier as Identifiers, and
// the mark type and word mark as properties.
package bimi

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

// Properties this plugin stores.
const (
	PropMarkType   = "mark_type"
	PropWordMark   = "word_mark"
	PropTMOffice   = "trademark_office"
	PropBIMILogo   = "bimi_logo"
	maxEvidenceLen = 256 << 10
)

// Mark certificate object identifiers (BIMI Group, Verified Mark Certificate
// Requirements v1.5, sections 7.1.2.3 and 7.1.4.2.2).
var (
	oidBIMIKeyUsage     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}
	oidTrademarkOffice  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 2}
	oidTrademarkCountry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 3}
	oidTrademarkID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 4}
	oidLEI              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 5}
	oidWordMark         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 6}
	oidMarkType         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 13}
)

type bimiPlugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
	rlimit *rate.Limiter
}

func NewBIMI() et.Plugin {
	return &bimiPlugin{
		name:   "BIMI",
		source: &et.Source{Name: "BIMI", Confidence: 100},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
	}
}

func (b *bimiPlugin) Name() string { return b.name }

func (b *bimiPlugin) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.TLSCertificate), string(oam.ContactRecord), string(oam.Identifier)},
		EventType:    oam.FQDN,
		Callback:     b.check,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bimiPlugin) Stop() { b.log.Info("Plugin stopped") }

func (b *bimiPlugin) check(e *et.Event) error {
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

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.TLSCertificate), b.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, b.source)

	rec, ok := b.record(e, apex)
	if !ok || rec.evidence == "" {
		return nil
	}
	cert := b.fetch(e, rec.evidence, apex)
	if cert == nil {
		return nil
	}
	b.store(e, cert, rec)
	return nil
}

// bimiRecord is a BIMI assertion record's tags.
type bimiRecord struct {
	logo, evidence string
}

// parseBIMI reads a BIMI assertion record: "v=BIMI1" first, then
// semicolon-separated tags, of which l= is the logo and a= the authority
// evidence (the mark certificate).
func parseBIMI(txt string) (bimiRecord, bool) {
	var r bimiRecord
	parts := strings.Split(txt, ";")
	if len(parts) == 0 || !strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", ""), "v=BIMI1") {
		return r, false
	}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "l":
			r.logo = v
		case "a":
			r.evidence = v
		}
	}
	return r, true
}

// record asks for the domain's default BIMI assertion record.
func (b *bimiPlugin) record(e *et.Event, apex string) (bimiRecord, bool) {
	rr, err := support.PerformQuery(e.Session.Ctx(), "default._bimi."+apex, dns.TypeTXT)
	if err != nil {
		return bimiRecord{}, false
	}
	for _, r := range rr {
		if t, ok := r.(*dns.TXT); ok {
			if rec, ok := parseBIMI(strings.Join(t.Txt, "")); ok {
				return rec, true
			}
		}
	}
	return bimiRecord{}, false
}

// fetch downloads the evidence document and returns the mark certificate in
// it that lists the domain, or nil.
func (b *bimiPlugin) fetch(e *et.Event, u, apex string) *x509.Certificate {
	if !strings.HasPrefix(strings.ToLower(u), "https://") {
		return nil
	}
	_ = support.WaitLimit(e.Session.Ctx(), b.rlimit)
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || len(resp.Body) > maxEvidenceLen {
		return nil
	}
	return markCertificate([]byte(resp.Body), apex, time.Now())
}

// markCertificate returns the first certificate in a PEM evidence document
// that is a mark certificate (the BIMI extended key usage), lists the domain
// among its names, and is valid at now.
func markCertificate(data []byte, apex string, now time.Time) *x509.Certificate {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		if !slices.ContainsFunc(cert.UnknownExtKeyUsage, oidBIMIKeyUsage.Equal) {
			continue
		}
		if slices.ContainsFunc(cert.DNSNames, func(n string) bool { return strings.EqualFold(n, apex) }) {
			return cert
		}
	}
}

// markDetails are what a mark certificate's subject says about the mark.
type markDetails struct {
	office, country, trademark, lei, wordMark, markType string
}

func subjectDetails(cert *x509.Certificate) markDetails {
	var d markDetails
	for _, atv := range cert.Subject.Names {
		v, ok := atv.Value.(string)
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case atv.Type.Equal(oidTrademarkOffice):
			d.office = v
		case atv.Type.Equal(oidTrademarkCountry):
			d.country = strings.ToUpper(v)
		case atv.Type.Equal(oidTrademarkID):
			d.trademark = v
		case atv.Type.Equal(oidLEI):
			d.lei = strings.ToUpper(v)
		case atv.Type.Equal(oidWordMark):
			d.wordMark = v
		case atv.Type.Equal(oidMarkType):
			d.markType = v
		}
	}
	return d
}

// subjectContactKey is the key the certificate handler gives a certificate's
// subject ContactRecord, so the mark details join the record it creates.
func subjectContactKey(cert *x509.Certificate) string {
	return "x509 Certificate: " + cert.SerialNumber.String() + ", Subject"
}

// store records the mark certificate and hands it to the certificate handler,
// which stores its names and subject, then adds the mark details to the
// subject ContactRecord.
func (b *bimiPlugin) store(e *et.Event, cert *x509.Certificate, rec bimiRecord) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	db := e.Session.DB()

	c := support.X509ToOAMTLSCertificate(cert)
	if c == nil {
		return
	}
	certEnt, err := db.CreateAsset(ctx, c)
	if err != nil || certEnt == nil {
		return
	}
	b.sourced(ctx, e, certEnt)
	if rec.logo != "" {
		b.property(ctx, e, certEnt, PropBIMILogo, rec.logo)
	}

	cr, err := db.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: subjectContactKey(cert)})
	if err == nil && cr != nil {
		b.link(ctx, e, certEnt, "subject_contact", cr)
		d := subjectDetails(cert)
		if d.markType != "" {
			b.property(ctx, e, cr, PropMarkType, d.markType)
		}
		if d.wordMark != "" {
			b.property(ctx, e, cr, PropWordMark, d.wordMark)
		}
		if d.trademark != "" && d.country != "" {
			id := d.country + ":" + d.trademark
			if ident := b.identifier(ctx, e, cr, general.TrademarkRegistration, id); ident != nil && d.office != "" {
				b.property(ctx, e, ident, PropTMOffice, d.office)
			}
		}
		if d.lei != "" {
			b.identifier(ctx, e, cr, general.LEICode, d.lei)
		}
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("TLSCertificate: %s", c.SerialNumber),
		Meta:    cert,
		Entity:  certEnt,
		Session: e.Session,
	})
	e.Session.Log().Info("mark certificate found", "domain", strings.Join(cert.DNSNames, ","),
		"organization", strings.Join(cert.Subject.Organization, ","),
		slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
}

func (b *bimiPlugin) identifier(ctx context.Context, e *et.Event, cr *dbt.Entity, kind, id string) *dbt.Entity {
	ent, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{UniqueID: kind + ":" + id, ID: id, Type: kind})
	if err != nil || ent == nil {
		return nil
	}
	b.sourced(ctx, e, ent)
	b.link(ctx, e, cr, "id", ent)
	return ent
}

func (b *bimiPlugin) sourced(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
}

func (b *bimiPlugin) property(ctx context.Context, e *et.Event, ent *dbt.Entity, name, value string) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

func (b *bimiPlugin) link(ctx context.Context, e *et.Event, from *dbt.Entity, label string, to *dbt.Entity) {
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
