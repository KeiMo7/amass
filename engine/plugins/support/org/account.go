// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// OrgCheckingAccount returns the organization's default checking account, the
// account the funds transfers collectors find (awards, grants, contracts,
// funding rounds, filings) are sent to or from, creating it when the
// organization has none. src is recorded as a source of the account and of
// the organization's account edge. It returns nil on a failure.
func OrgCheckingAccount(sess et.Session, orgent *dbt.Entity, src *et.Source) *dbt.Entity {
	o, ok := orgent.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var accountent *dbt.Entity
	if accts := checkingAccounts(ctx, sess, orgent, time.Time{}, nil); len(accts) > 0 {
		accountent = accts[0]
	} else {
		ent, err := sess.DB().CreateAsset(ctx, &oamacct.Account{
			ID:     "org-account:" + o.Name,
			Type:   oamacct.Checking,
			Number: "default",
			Active: o.Active,
		})
		if err != nil || ent == nil {
			return nil
		}
		accountent = ent
	}

	if _, err := sess.DB().CreateEntityProperty(ctx, accountent, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	}); err != nil {
		return nil
	}

	if err := createRelation(ctx, sess, orgent, &oamgen.SimpleRelation{Name: "account"}, accountent, src); err != nil {
		return nil
	}
	return accountent
}

// OrgTransfersReceived returns the funds transfers src recorded since the
// time into the organization's default checking account, through account and
// recipient edges src vouches for, so a collector within its TTL can answer
// from the database.
func OrgTransfersReceived(sess et.Session, orgent *dbt.Entity, since time.Time, src *et.Source) []*dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var fundents []*dbt.Entity
	for _, acct := range checkingAccounts(ctx, sess, orgent, since, src) {
		edges, err := sess.DB().IncomingEdges(ctx, acct, since, "recipient")
		if err != nil {
			continue
		}
		for _, edge := range edges {
			if !sourcedEdge(ctx, sess, edge, since, src) {
				continue
			}
			if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamfin.FundsTransfer); ok {
					fundents = append(fundents, a)
				}
			}
		}
	}
	return fundents
}

// checkingAccounts returns the organization's default checking accounts over
// account edges seen since the time, only those src vouches for when src is
// not nil.
func checkingAccounts(ctx context.Context, sess et.Session, orgent *dbt.Entity, since time.Time, src *et.Source) []*dbt.Entity {
	edges, err := sess.DB().OutgoingEdges(ctx, orgent, since, "account")
	if err != nil {
		return nil
	}

	var accts []*dbt.Entity
	for _, edge := range edges {
		if src != nil && !sourcedEdge(ctx, sess, edge, since, src) {
			continue
		}
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
			if acc, ok := a.Asset.(*oamacct.Account); ok && acc.Type == oamacct.Checking && acc.Number == "default" {
				accts = append(accts, a)
			}
		}
	}
	return accts
}

// sourcedEdge reports whether src vouched for the edge since the time.
func sourcedEdge(ctx context.Context, sess et.Session, edge *dbt.Edge, since time.Time, src *et.Source) bool {
	tags, err := sess.DB().FindEdgeTags(ctx, edge, since, src.Name)
	return err == nil && len(tags) > 0
}
