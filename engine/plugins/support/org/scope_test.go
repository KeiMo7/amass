// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"net/netip"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func TestInScope(t *testing.T) {
	sess := plugintest.NewSession(t)
	target := sess.Asset(t, &oamorg.Organization{ID: "ithaca:test", Name: "ithaca college"})
	vendor := sess.Asset(t, &oamorg.Organization{ID: "adobe:test", Name: "adobe"})

	if InScope(sess, target) || InScope(sess, vendor) {
		t.Fatal("an organization was in scope before anything was")
	}

	sess.Scope().Add(target.Asset)
	if !InScope(sess, target) {
		t.Error("the organization in scope is not")
	}
	if InScope(sess, vendor) {
		t.Error("a vendor outside the scope is in it")
	}

	// Only organizations are judged; other assets and nil are not in scope here.
	name := sess.Asset(t, &oamdns.FQDN{Name: "www.ithaca.edu"})
	if InScope(sess, name) || InScope(sess, nil) || InScope(nil, target) {
		t.Error("something other than an organization was in scope")
	}
}

func TestContactInScope(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddDomain("ithaca.edu")

	// The target's registrant address, reached from its domain's registration
	// record, belongs to the enumeration.
	record := sess.Asset(t, &oamreg.DomainRecord{Domain: "ithaca.edu", Name: "ithaca.edu"})
	registrant := sess.Asset(t, &oamcontact.ContactRecord{DiscoveredAt: "https://rdap.example/domain/ithaca.edu"})
	home := sess.Asset(t, &oamcontact.StreetAddress{Address: "953 Danby Road Ithaca NY 14850 US",
		BuildingNumber: "953", StreetName: "Danby Road", City: "Ithaca", Country: "US"})
	sess.Edge(t, record, &oamgen.SimpleRelation{Name: "registrant_contact"}, registrant)
	sess.Edge(t, registrant, &oamgen.SimpleRelation{Name: "street_address"}, home)

	// A network operator's address, reached from the registration record of a
	// netblock the target's names point into, does not.
	netrec := sess.Asset(t, &oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("20.0.0.0/11"), Handle: "NET-20-0-0-0-1",
		StartAddress: netip.MustParseAddr("20.0.0.0"), EndAddress: netip.MustParseAddr("20.31.255.255"),
		Type: "IPv4", Name: "MSFT"})
	operator := sess.Asset(t, &oamcontact.ContactRecord{DiscoveredAt: "https://rdap.example/entity/MSFT"})
	vendor := sess.Asset(t, &oamorg.Organization{ID: "msft:test", Name: "microsoft corporation"})
	away := sess.Asset(t, &oamcontact.StreetAddress{Address: "1 Microsoft Way Redmond WA 98052 US",
		BuildingNumber: "1", StreetName: "Microsoft Way", City: "Redmond", Country: "US"})
	sess.Edge(t, netrec, &oamgen.SimpleRelation{Name: "registrant"}, operator)
	sess.Edge(t, operator, &oamgen.SimpleRelation{Name: "organization"}, vendor)
	sess.Edge(t, operator, &oamgen.SimpleRelation{Name: "street_address"}, away)

	if !ContactInScope(sess, home) {
		t.Error("the target's registrant address is not in scope")
	}
	if ContactInScope(sess, away) {
		t.Error("a network operator's address is in scope")
	}

	// Once the operator's organization is in scope, its address is too.
	sess.Scope().Add(vendor.Asset)
	if !ContactInScope(sess, away) {
		t.Error("the address of an organization in scope is not")
	}

	// A phone is in scope when the session was seeded with it.
	phone := sess.Asset(t, &oamcontact.Phone{Raw: "+1 (607) 274-3011", E164: "+16072743011"})
	if ContactInScope(sess, phone) {
		t.Error("a phone nothing holds is in scope")
	}
	sess.Config().AddPhone("+1 607 274 3011")
	if !ContactInScope(sess, phone) {
		t.Error("the seed phone is not in scope")
	}

	// The registrar of the target's domain is not the target.
	registrar := sess.Asset(t, &oamcontact.ContactRecord{DiscoveredAt: "https://rdap.example/registrar/1"})
	desk := sess.Asset(t, &oamcontact.StreetAddress{Address: "100 Registrar Lane Reston VA 20190 US",
		BuildingNumber: "100", StreetName: "Registrar Lane", City: "Reston", Country: "US"})
	sess.Edge(t, record, &oamgen.SimpleRelation{Name: "registrar_contact"}, registrar)
	sess.Edge(t, registrar, &oamgen.SimpleRelation{Name: "street_address"}, desk)
	if ContactInScope(sess, desk) {
		t.Error("the registrar's address is in scope")
	}

	if ContactInScope(sess, record) || ContactInScope(sess, nil) || ContactInScope(nil, home) {
		t.Error("something other than a phone or street address was in scope")
	}
}
