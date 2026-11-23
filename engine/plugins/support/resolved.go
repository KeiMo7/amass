// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// maxResolvingNames bounds the names AddressInScope reads for one address,
// and maxAliasDepth how far back along CNAME records it looks.
const (
	maxResolvingNames = 25
	maxAliasDepth     = 4
)

// AddressInScope reports whether an IP address belongs to the enumeration:
// it is in the session's scope, or an in-scope name resolves to it, directly
// or through aliases (an in-scope name with a CNAME to a provider's name that
// has the address). An enumeration of a domain scopes names, not addresses,
// so the addresses its names resolve to count as its hosting.
func AddressInScope(sess et.Session, ipent *dbt.Entity) bool {
	if sess == nil || ipent == nil {
		return false
	}
	ip, ok := ipent.Asset.(*oamnet.IPAddress)
	if !ok {
		return false
	}
	if _, conf := sess.Scope().IsAssetInScope(ip, 0); conf > 0 {
		return true
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	// Walk back from the address over dns_record edges (A/AAAA, then CNAME),
	// a level at a time, until an in-scope name is found.
	seen := map[string]bool{ipent.ID: true}
	level := []*dbt.Entity{ipent}
	read := 0
	for depth := 0; depth <= maxAliasDepth && len(level) > 0 && read < maxResolvingNames; depth++ {
		var next []*dbt.Entity
		for _, to := range level {
			edges, err := sess.DB().IncomingEdges(ctx, to, time.Time{}, "dns_record")
			if err != nil {
				continue
			}
			for _, edge := range edges {
				if read >= maxResolvingNames {
					break
				}
				if seen[edge.FromEntity.ID] {
					continue
				}
				seen[edge.FromEntity.ID] = true
				read++

				from, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
				if err != nil || from == nil {
					continue
				}
				fqdn, ok := from.Asset.(*oamdns.FQDN)
				if !ok {
					continue
				}
				if _, conf := sess.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
					return true
				}
				next = append(next, from)
			}
		}
		level = next
	}
	return false
}
