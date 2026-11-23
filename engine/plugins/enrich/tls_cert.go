// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type tlsexpand struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *et.Source
}

func NewTLSCerts() et.Plugin {
	return &tlsexpand{
		name: "TLSCert-Expansion",
		transforms: []string{
			string(oam.URL),
			string(oam.FQDN),
			string(oam.IPAddress),
			string(oam.ContactRecord),
			string(oam.Organization),
			string(oam.StreetAddress),
			string(oam.Identifier),
			string(oam.TLSCertificate),
		},
		source: &et.Source{
			Name:       "TLSCert-Expansion",
			Confidence: 100,
		},
	}
}

func (te *tlsexpand) Name() string {
	return te.name
}

func (te *tlsexpand) Start(r et.Registry) error {
	te.log = r.Log().WithGroup("plugin").With("name", te.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       te,
		Name:         te.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   te.transforms,
		EventType:    oam.TLSCertificate,
		Callback:     te.check,
	}); err != nil {
		return err
	}

	te.log.Info("Plugin started")
	return nil
}

func (te *tlsexpand) Stop() {
	te.log.Info("Plugin stopped")
}

func (te *tlsexpand) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamcert.TLSCertificate)
	if !ok {
		return errors.New("failed to extract the TLSCertificate asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.TLSCertificate), append(te.transforms, te.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	var findings []*support.Finding
	if cert, ok := e.Meta.(*x509.Certificate); ok && cert != nil {
		te.store(e, cert, e.Entity, matches)
	} else {
		t := e.Entity.Asset.(*oamcert.TLSCertificate)
		findings = support.StoredFindings(e, e.Entity, "TLSCertificate: "+t.SerialNumber, te.name, matches,
			map[string][]string{
				string(oam.URL):            {"san_url", "ocsp_server", "issuing_certificate_url"},
				string(oam.FQDN):           {"common_name", "san_dns_name"},
				string(oam.ContactRecord):  {"subject_contact", "issuer_contact"},
				string(oam.IPAddress):      {"san_ip_address"},
				string(oam.Identifier):     {"san_email_address"},
				string(oam.TLSCertificate): {"issuing_certificate"},
			}, te.source)
	}

	if len(findings) > 0 {
		te.process(e, findings)
	}
	return nil
}

func (te *tlsexpand) store(e *et.Event, cert *x509.Certificate, asset *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	t := asset.Asset.(*oamcert.TLSCertificate)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Minute)
	defer cancel()

	if m.IsMatch(string(oam.FQDN)) {
		if common := t.SubjectCommonName; common != "" {
			for _, name := range support.ScrapeSubdomainNames(strings.ToLower(strings.TrimSpace(common))) {
				if a, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "TLSCertificate: " + t.SerialNumber,
						To:       a,
						ToName:   name,
						Rel:      &general.SimpleRelation{Name: "common_name"},
					})
				}
			}
		}
		for _, n := range cert.DNSNames {
			for _, name := range support.ScrapeSubdomainNames(strings.ToLower(strings.TrimSpace(n))) {
				if a, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "TLSCertificate: " + t.SerialNumber,
						To:       a,
						ToName:   name,
						Rel:      &general.SimpleRelation{Name: "san_dns_name"},
					})
				}
			}
		}
	}

	if m.IsMatch(string(oam.Identifier)) {
		for _, emailstr := range cert.EmailAddresses {
			email := strings.ToLower(strings.TrimSpace(emailstr))
			if email == "" {
				continue
			}

			if a, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
				UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, email),
				ID:       email,
				Type:     general.EmailAddress,
			}); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "TLSCertificate: " + t.SerialNumber,
					To:       a,
					ToName:   email,
					Rel:      &general.SimpleRelation{Name: "san_email_address"},
				})
			}
		}
	}

	if m.IsMatch(string(oam.IPAddress)) {
		for _, ip := range cert.IPAddresses {
			oamip := &network.IPAddress{Address: netip.MustParseAddr(ip.String())}

			if oamip.Address.Is4() {
				oamip.Type = "IPv4"
			} else {
				oamip.Type = "IPv6"
			}

			if a, err := e.Session.DB().CreateAsset(ctx, oamip); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "TLSCertificate: " + t.SerialNumber,
					To:       a,
					ToName:   oamip.Address.String(),
					Rel:      &general.SimpleRelation{Name: "san_ip_address"},
				})
			}
		}
	}

	if m.IsMatch(string(oam.URL)) {
		for _, u := range cert.URIs {
			if oamurl := support.RawURLToOAM(u.String()); oamurl != nil {
				if a, err := e.Session.DB().CreateAsset(ctx, oamurl); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "TLSCertificate: " + t.SerialNumber,
						To:       a,
						ToName:   oamurl.Raw,
						Rel:      &general.SimpleRelation{Name: "san_url"},
					})
				}
			}
		}
		for _, u := range cert.IssuingCertificateURL {
			if oamurl := support.RawURLToOAM(u); oamurl != nil {
				if a, err := e.Session.DB().CreateAsset(ctx, oamurl); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "TLSCertificate: " + t.SerialNumber,
						To:       a,
						ToName:   oamurl.Raw,
						Rel:      &general.SimpleRelation{Name: "issuing_certificate_url"},
					})
				}
			}
		}
		for _, u := range cert.OCSPServer {
			if oamurl := support.RawURLToOAM(u); oamurl != nil {
				if a, err := e.Session.DB().CreateAsset(ctx, oamurl); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "TLSCertificate: " + t.SerialNumber,
						To:       a,
						ToName:   oamurl.Raw,
						Rel:      &general.SimpleRelation{Name: "ocsp_server"},
					})
				}
			}
		}
	}

	// process the relations built so far from the certificate
	support.ProcessAssetsWithSource(e, findings, te.source, te.name, te.name+"-Handler")

	if m.IsMatch(string(oam.ContactRecord)) {
		contacts := []*tlsContact{
			{&cert.Subject, "subject_contact", support.X509ContactKey(cert, "Subject")},
			{&cert.Issuer, "issuer_contact", support.X509ContactKey(cert, "Issuer")},
		}
		for _, c := range contacts {
			te.storeContact(e, c, asset, te.source, m)
		}
	}
}

type tlsContact struct {
	contact      *pkix.Name
	RelationName string
	DiscoveredAt string
}

func (te *tlsexpand) storeContact(e *et.Event, c *tlsContact, asset *dbt.Entity, src *et.Source, m *config.Matches) {
	ct := c.contact

	var foundaddr bool
	if len(ct.Province) > 0 && len(ct.Country) > 0 {
		foundaddr = true
	}

	var foundorgs bool
	if len(ct.Organization) > 0 {
		foundorgs = true
	}
	// only continue with the database operations if there's a contact record to create
	if !foundaddr && !foundorgs {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: c.DiscoveredAt})
	if err != nil || cr == nil {
		return
	}

	if foundaddr && m.IsMatch(string(oam.StreetAddress)) {
		var addr string
		fields := [][]string{
			ct.Organization,
			ct.StreetAddress,
			ct.Locality,
			ct.Province,
			ct.PostalCode,
			ct.Country,
		}
		for _, field := range fields {
			if len(field) > 0 && field[0] != "" {
				addr += " " + field[0]
			}
		}

		if loc := support.ParseStreetAddress(strings.TrimSpace(addr)); loc != nil {
			if a, err := e.Session.DB().CreateAsset(ctx, loc); err == nil && a != nil {
				if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
					Relation:   &general.SimpleRelation{Name: "street_address"},
					FromEntity: cr,
					ToEntity:   a,
				}); err == nil && edge != nil {
					_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
				_ = e.Dispatcher.DispatchEvent(&et.Event{
					Name:    loc.Address,
					Entity:  a,
					Session: e.Session,
				})
			}
		}
	}
	if len(ct.OrganizationalUnit) > 0 && ct.OrganizationalUnit[0] != "" && m.IsMatch(string(oam.URL)) {
		if u := support.ExtractURLFromString(ct.OrganizationalUnit[0]); u != nil {
			if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
				if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
					Relation:   &general.SimpleRelation{Name: "url"},
					FromEntity: cr,
					ToEntity:   a,
				}); err == nil && edge != nil {
					_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			}
		}
	}

	var findings []*support.Finding
	t := asset.Asset.(*oamcert.TLSCertificate)
	findings = append(findings, &support.Finding{
		From:     asset,
		FromName: "TLSCertificate: " + t.SerialNumber,
		To:       cr,
		ToName:   "ContactRecord" + c.DiscoveredAt,
		Rel:      &general.SimpleRelation{Name: c.RelationName},
	})
	// process the relation immediately
	support.ProcessAssetsWithSource(e, findings, te.source, te.name, te.name+"-Handler")

	// the organization must come last due to a potential chicken-and-egg problem
	if m.IsMatch(string(oam.Organization)) && len(ct.Organization) > 0 && ct.Organization[0] != "" {
		orgent, err := org.CreateOrgAsset(e.Session, cr,
			&general.SimpleRelation{Name: "organization"},
			&oamorg.Organization{Name: ct.Organization[0]}, src)

		if err == nil && orgent != nil {
			o := orgent.Asset.(*oamorg.Organization)

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
				Entity:  orgent,
				Session: e.Session,
			})
		}
	}
}

func (te *tlsexpand) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, te.source, te.name, te.name+"-Handler")
}
