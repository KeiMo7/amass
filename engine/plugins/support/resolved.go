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

// maxResolvingNames bounds the names AddressInScope reads for one address.
const maxResolvingNames = 25

// AddressInScope reports whether an IP address belongs to the enumeration:
// it is in the session's scope, or an in-scope name resolves to it (a
// dns_record from that name). An enumeration of a domain scopes names, not
// addresses, so the addresses its names resolve to count as its hosting.
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

	edges, err := sess.DB().IncomingEdges(ctx, ipent, time.Time{}, "dns_record")
	if err != nil {
		return false
	}
	for i, edge := range edges {
		if i >= maxResolvingNames {
			break
		}
		from, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || from == nil {
			continue
		}
		if fqdn, ok := from.Asset.(*oamdns.FQDN); ok {
			if _, conf := sess.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
				return true
			}
		}
	}
	return false
}
