// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"strings"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// inScopeOrgs remembers the organizations found in a session's scope, by
// session and entity ID. Only positive answers are kept: an organization can
// become associated with the scope as the enumeration learns more.
var inScopeOrgs sync.Map

// InScope reports whether the organization belongs to the enumeration: it is
// in the session's scope, or it is associated with assets in scope (the
// registrant of an in-scope domain, for one), even when the scope may not be
// expanded. A vendor or provider the target merely uses is not. Collectors
// that fan out from an organization (its corporate family, funding, phones,
// other domains) run only for these; identifying an organization (its name,
// LEI, jurisdiction) runs for every organization, so third parties are still
// recognized.
func InScope(sess et.Session, orgent *dbt.Entity) bool {
	if sess == nil || orgent == nil {
		return false
	}
	if _, ok := orgent.Asset.(*oamorg.Organization); !ok {
		return false
	}

	key := sess.ID().String() + ":" + orgent.ID
	if _, found := inScopeOrgs.Load(key); found {
		return true
	}

	in := false
	if _, conf := sess.Scope().IsAssetInScope(orgent.Asset, 0); conf > 0 {
		in = true
	} else if assocs, err := sess.Scope().IsAssociated(&et.Association{Submission: orgent}); err == nil && len(assocs) > 0 {
		in = true
	}
	if in {
		inScopeOrgs.Store(key, true)
	}
	return in
}

// maxContactEdges bounds how many edges ContactInScope reads at each step, so
// a widely shared address costs a bounded number of reads.
const maxContactEdges = 50

// inScopeContacts remembers, like inScopeOrgs, the phones and street
// addresses found to belong to a session's enumeration.
var inScopeContacts sync.Map

// ContactInScope reports whether a phone number or street address belongs to
// the enumeration: it is one of the session's seeds (a phone or address
// pivot), or a contact record holding it belongs to an organization in scope
// (InScope) or is one an in-scope domain registration record, web page or
// certificate names as its own (semantics.OwnContactLabels). A domain's
// registrar and a certificate's issuer are not the enumeration's, and neither
// is a network operator's address from the registration record of a netblock
// the target's names point into.
// Reverse lookups from a phone or address run only for these, so a vendor's
// contact details are stored but not searched.
func ContactInScope(sess et.Session, ent *dbt.Entity) bool {
	if sess == nil || ent == nil {
		return false
	}

	key := sess.ID().String() + ":" + ent.ID
	if _, found := inScopeContacts.Load(key); found {
		return true
	}

	in := false
	switch v := ent.Asset.(type) {
	case *oamcontact.Phone:
		in = phoneSeed(sess, v)
	case *oamcontact.StreetAddress:
		_, conf := sess.Scope().IsAssetInScope(v, 0)
		in = conf > 0
	default:
		return false
	}
	if !in {
		in = heldInScope(sess, ent)
	}

	if in {
		inScopeContacts.Store(key, true)
	}
	return in
}

// phoneSeed reports whether the phone is one the session was seeded with.
func phoneSeed(sess et.Session, ph *oamcontact.Phone) bool {
	cfg := sess.Config()
	if cfg == nil || cfg.Scope == nil {
		return false
	}

	want := digits(ph.E164)
	if want == "" {
		want = digits(ph.Raw)
	}
	for _, p := range cfg.Scope.Phones {
		if want != "" && digits(p) == want {
			return true
		}
	}
	return false
}

func digits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// heldInScope reports whether an organization in scope, or a contact record
// of an in-scope domain, registration record or web page, holds the entity.
func heldInScope(sess et.Session, ent *dbt.Entity) bool {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	for _, holder := range neighbors(ctx, sess, ent, true) {
		switch holder.Asset.(type) {
		case *oamorg.Organization:
			if InScope(sess, holder) {
				return true
			}
		case *oamcontact.ContactRecord:
			for _, o := range neighbors(ctx, sess, holder, false, "organization") {
				if InScope(sess, o) {
					return true
				}
			}
			for _, from := range neighbors(ctx, sess, holder, true, semantics.OwnContactLabels...) {
				if inScopeSource(sess, from) {
					return true
				}
			}
		}
	}
	return false
}

// inScopeSource reports whether a contact record's source is an in-scope
// domain registration record, web page or certificate. Netblock and
// autonomous system records are left out: they name the network's operator,
// often a provider the target merely uses.
func inScopeSource(sess et.Session, ent *dbt.Entity) bool {
	switch ent.Asset.(type) {
	case *oamreg.DomainRecord, *oamurl.URL, *oamcert.TLSCertificate:
		_, conf := sess.Scope().IsAssetInScope(ent.Asset, 0)
		return conf > 0
	}
	return false
}

// neighbors returns up to maxContactEdges entities at the other end of the
// entity's incoming (or outgoing) edges with the labels, all labels when
// none are given.
func neighbors(ctx context.Context, sess et.Session, ent *dbt.Entity, incoming bool, labels ...string) []*dbt.Entity {
	var edges []*dbt.Edge
	var err error
	if incoming {
		edges, err = sess.DB().IncomingEdges(ctx, ent, time.Time{}, labels...)
	} else {
		edges, err = sess.DB().OutgoingEdges(ctx, ent, time.Time{}, labels...)
	}
	if err != nil {
		return nil
	}

	var out []*dbt.Entity
	for i, edge := range edges {
		if i >= maxContactEdges {
			break
		}

		id := edge.ToEntity.ID
		if incoming {
			id = edge.FromEntity.ID
		}
		if other, err := sess.DB().FindEntityById(ctx, id); err == nil && other != nil {
			out = append(out, other)
		}
	}
	return out
}
